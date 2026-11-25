"""Load Sigma-style YAML rules and match them against web requests and Linux auth logs.

Sigma (https://github.com/SigmaHQ/sigma) is the common format SOC teams use to share
detection rules. LogSentinel supports a deliberately small subset of it:

* ``logsource``: ``category: webserver`` (``product`` apache / nginx or absent), or
  ``product: linux`` with ``service: auth`` / ``sshd`` (keyword lists only, as in Sigma's
  own Linux rules, since syslog lines have no standard fields)
* fields from the Sigma web taxonomy: ``c-ip``, ``cs-method``, ``cs-uri``, ``cs-uri-stem``,
  ``cs-uri-query``, ``cs-version``, ``sc-status``, ``sc-bytes``, ``c-useragent``, ``cs-referer``
* values: case-insensitive, ``*`` / ``?`` wildcards, lists mean OR, ``null`` means empty
* modifiers: ``contains``, ``startswith``, ``endswith``, ``all``, ``re`` (with ``i``)
* keyword lists (searched in the raw log line)
* conditions: ``and``, ``or``, ``not``, parentheses, ``1 of x*``, ``all of x*``, ``... of them``

Anything else (aggregations, timeframes, other log sources, unknown modifiers) is rejected
with a clear error instead of being silently ignored: a rule that loads but never fires
is worse than one that fails to load.

URL and header fields are matched both as logged and after ``normalize()`` (URL decoding,
SQL comment removal...), so a rule written for ``' or 1=1`` also catches ``%27%20or%201%3D1``.
"""
from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from logsentinel.detectors.web import normalize
from logsentinel.models import HttpEvent, LogLine, Severity

Predicate = Callable[[HttpEvent | LogLine], bool]

WEB = "webserver"
LINUX = "linux"


class RuleError(ValueError):
    """A rule file cannot be loaded (invalid, or uses unsupported Sigma features)."""


_SEVERITY = {
    "informational": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _stem(e: HttpEvent) -> str:
    return e.path.split("?", 1)[0]


def _query(e: HttpEvent) -> str:
    return e.path.split("?", 1)[1] if "?" in e.path else ""


# Sigma field name -> (value getter, also match the normalized value?)
_FIELDS: dict[str, tuple[Callable[[HttpEvent], str], bool]] = {
    "c-ip": (lambda e: e.source_ip, False),
    "cs-method": (lambda e: e.method, False),
    "cs-uri": (lambda e: e.path, True),
    "cs-uri-stem": (_stem, True),
    "cs-uri-query": (_query, True),
    "cs-version": (lambda e: e.protocol, False),
    "sc-status": (lambda e: str(e.status), False),
    "sc-bytes": (lambda e: str(e.size), False),
    "c-useragent": (lambda e: e.user_agent, True),
    "cs-user-agent": (lambda e: e.user_agent, True),
    "cs-referer": (lambda e: e.referrer, True),
    "cs-referrer": (lambda e: e.referrer, True),
}

_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i"}


@dataclass(frozen=True)
class SigmaRule:
    rule_id: str
    title: str
    severity: Severity
    mitre_technique: str
    source: str            # file the rule came from, for error messages and reports
    logsource: str         # WEB or LINUX: which command the rule applies to
    _match: Predicate

    def matches(self, event: HttpEvent | LogLine) -> bool:
        return self._match(event)


# --------------------------------------------------------------------------- values


def _wildcard(value: str) -> str:
    r"""Sigma plain value -> regex body. ``*`` any run, ``?`` one char, ``\*`` ``\?`` ``\\`` literal."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _value_pattern(value: object, mods: set[str]) -> re.Pattern[str]:
    text = "" if value is None else str(value)
    if "re" in mods:
        # Sigma regexes are case-sensitive unless the "i" modifier is given.
        flags = re.DOTALL | (re.IGNORECASE if "i" in mods else 0)
        try:
            return re.compile(text, flags)
        except re.error as exc:
            raise RuleError(f"invalid regular expression {text!r}: {exc}") from None
    body = _wildcard(text)
    if "contains" in mods:
        pass
    elif "startswith" in mods:
        body = "^" + body
    elif "endswith" in mods:
        body += "$"
    else:
        body = f"^{body}$"
    return re.compile(body, re.IGNORECASE | re.DOTALL)


def _field_predicate(key: str, values: object) -> Predicate:
    name, *mods = key.split("|")
    if name not in _FIELDS:
        raise RuleError(f"unsupported field {name!r} (supported: {', '.join(sorted(_FIELDS))})")
    unknown = set(mods) - _MODIFIERS
    if unknown:
        raise RuleError(f"unsupported modifier(s) {', '.join(sorted(unknown))} on field {name!r}")
    mod_set = set(mods)
    if "i" in mod_set and "re" not in mod_set:
        raise RuleError(f"modifier 'i' only applies to 're' (field {name!r})")
    getter, decode = _FIELDS[name]

    items = values if isinstance(values, list) else [values]
    if any(isinstance(v, (dict, list)) for v in items):
        raise RuleError(f"field {name!r} needs plain values")
    if values is None:
        return lambda e: getter(e) == ""

    patterns = [_value_pattern(v, mod_set) for v in items]
    combine = all if "all" in mod_set else any

    def pred(e: HttpEvent) -> bool:
        raw = getter(e)
        candidates = (raw, normalize(raw)) if decode and raw else (raw,)
        return combine(any(p.search(c) for c in candidates) for p in patterns)

    return pred


def _keywords_predicate(words: list, decode: bool) -> Predicate:
    if any(isinstance(w, (dict, list)) for w in words):
        raise RuleError("keyword lists must hold plain strings")
    patterns = [_value_pattern(w, {"contains"}) for w in words]

    def pred(e: HttpEvent | LogLine) -> bool:
        candidates = (e.raw, normalize(e.raw)) if decode else (e.raw,)
        return any(p.search(c) for p in patterns for c in candidates)

    return pred


def _selection(body: object, kind: str) -> Predicate:
    """A detection identifier: a map (AND of fields), a list of maps (OR), or keywords."""
    if kind == LINUX:
        if isinstance(body, list) and body and not any(isinstance(x, dict) for x in body):
            return _keywords_predicate(body, decode=False)
        raise RuleError("linux rules support keyword lists only (syslog lines have no standard fields)")
    if isinstance(body, dict):
        if not body:
            raise RuleError("empty selection")
        preds = [_field_predicate(str(k), v) for k, v in body.items()]
        return lambda e: all(p(e) for p in preds)
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        preds = [_selection(x, kind) for x in body]
        return lambda e: any(p(e) for p in preds)
    if isinstance(body, list) and body:
        return _keywords_predicate(body, decode=True)
    raise RuleError(f"unsupported selection: {body!r}")


# ------------------------------------------------------------------------ condition

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class _Condition:
    """Recursive-descent parser: or < and < not < (group | quantifier | identifier)."""

    def __init__(self, text: str, selections: dict[str, Predicate]) -> None:
        if "|" in text:
            raise RuleError("aggregations in conditions (count(), near...) are not supported")
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.sel = selections

    def parse(self) -> Predicate:
        if not self.tokens:
            raise RuleError("empty condition")
        pred = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected {self.tokens[self.pos]!r} in condition")
        return pred

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        if self.pos >= len(self.tokens):
            raise RuleError("condition ends too early")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _or(self) -> Predicate:
        parts = [self._and()]
        while self._peek() == "or":
            self._next()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda e: any(p(e) for p in parts))

    def _and(self) -> Predicate:
        parts = [self._not()]
        while self._peek() == "and":
            self._next()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda e: all(p(e) for p in parts))

    def _not(self) -> Predicate:
        if self._peek() == "not":
            self._next()
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self) -> Predicate:
        tok = self._next()
        low = tok.lower()
        if tok == "(":
            inner = self._or()
            if self._peek() != ")":
                raise RuleError("missing ')' in condition")
            self._next()
            return inner
        if low in ("1", "any", "all") and self._peek() == "of":
            self._next()
            target = self._next()
            if target.lower() == "them":
                names = [n for n in self.sel if not n.startswith("_")]
            else:
                names = [n for n in self.sel if fnmatch.fnmatchcase(n, target)]
            if not names:
                raise RuleError(f"'{tok} of {target}' matches no selection")
            preds = [self.sel[n] for n in names]
            if low == "all":
                return lambda e: all(p(e) for p in preds)
            return lambda e: any(p(e) for p in preds)
        if tok not in self.sel:
            raise RuleError(f"condition refers to unknown selection {tok!r}")
        return self.sel[tok]


# --------------------------------------------------------------------------- rules


def _mitre(tags: object) -> str:
    found = []
    for tag in tags if isinstance(tags, list) else []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.IGNORECASE)
        if m:
            found.append(m.group(1).upper())
    return ", ".join(found) or "-"


def _logsource_kind(logsource: object) -> str:
    if not isinstance(logsource, dict):
        raise RuleError("'logsource' must be a mapping")
    if logsource.get("category") == "webserver":
        if logsource.get("product") not in (None, "apache", "nginx"):
            raise RuleError(f"unsupported logsource product {logsource['product']!r}")
        return WEB
    if logsource.get("product") == "linux" and logsource.get("service") in ("auth", "sshd"):
        return LINUX
    raise RuleError(
        "supported log sources: 'category: webserver', or 'product: linux' with 'service: auth' or 'sshd'"
    )


def load_rule(data: object, source: str = "<rule>") -> SigmaRule:
    """Build a rule from an already-parsed YAML document (a dict)."""
    try:
        if not isinstance(data, dict):
            raise RuleError("a rule must be a YAML mapping")
        if "action" in data:
            raise RuleError("rule collections (action: global/reset/repeat) are not supported")
        for key in ("title", "logsource", "detection"):
            if key not in data:
                raise RuleError(f"missing required key {key!r}")

        kind = _logsource_kind(data["logsource"])

        detection = data["detection"]
        if not isinstance(detection, dict):
            raise RuleError("'detection' must be a mapping")
        if "timeframe" in detection:
            raise RuleError("'timeframe' (correlation) is not supported")
        condition = detection.get("condition")
        if condition is None:
            raise RuleError("detection has no 'condition'")
        selections = {str(k): _selection(v, kind) for k, v in detection.items() if k != "condition"}
        conditions = condition if isinstance(condition, list) else [condition]
        preds = [_Condition(str(c), selections).parse() for c in conditions]

        level = str(data.get("level", "medium")).lower()
        if level not in _SEVERITY:
            raise RuleError(f"unknown level {level!r}")

        return SigmaRule(
            rule_id=str(data.get("id") or Path(source).stem),
            title=str(data["title"]),
            severity=_SEVERITY[level],
            mitre_technique=_mitre(data.get("tags")),
            source=source,
            logsource=kind,
            _match=preds[0] if len(preds) == 1 else (lambda e: any(p(e) for p in preds)),
        )
    except RuleError as exc:
        raise RuleError(f"{source}: {exc}") from None


def _rule_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(f for f in p.rglob("*") if f.suffix in (".yml", ".yaml"))
        elif p.is_file():
            files.append(p)
        else:
            raise RuleError(f"{p}: no such file or directory")
    return files


def load_rules(paths: Iterable[str | Path]) -> list[SigmaRule]:
    """Load every .yml / .yaml rule from the given files and directories.

    PyYAML is an optional dependency, imported only here, so the built-in detections keep
    working with no third-party packages installed.
    """
    try:
        import yaml
    except ImportError:
        raise RuleError("loading rules needs PyYAML: pip install 'logsentinel[yaml]'") from None

    rules = []
    for f in _rule_files(paths):
        try:
            # safe_load_all: never builds arbitrary Python objects from the file.
            docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            raise RuleError(f"{f}: invalid YAML: {exc}") from None
        rules += [load_rule(doc, str(f)) for doc in docs if doc is not None]
    return rules
