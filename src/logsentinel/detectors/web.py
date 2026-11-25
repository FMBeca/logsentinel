"""Web attack detection for Apache / Nginx access logs.

Two kinds of detection:

* **Signatures** (per request): regexes over the decoded request for SQL injection,
  cross-site scripting, path traversal and Log4Shell, plus known scanner User-Agents.
* **Behaviour** (per source IP): many distinct paths answered with 403/404 in a short
  window means someone is brute-forcing directories with a wordlist. This catches
  scanners that hide their User-Agent, which any tool can do with a single flag.

MITRE ATT&CK: T1190 - Exploit Public-Facing Application,
T1595.002 - Vulnerability Scanning, T1595.003 - Wordlist Scanning.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING
from urllib.parse import unquote_plus

from logsentinel.models import Alert, HttpEvent, Severity

if TYPE_CHECKING:  # sigma imports normalize() from here, so only import it for type hints
    from logsentinel.sigma import SigmaRule

MAX_SAMPLES = 5


@dataclass(frozen=True)
class Signature:
    """A detection rule matched against a single request.

    Built-in rules stay in Python so they work with no dependencies; extra rules can be
    loaded from Sigma-style YAML files (see logsentinel.sigma).
    """

    rule_id: str
    title: str
    severity: Severity
    mitre_technique: str
    patterns: tuple[re.Pattern[str], ...]
    fields: tuple[str, ...] = ("path",)   # HttpEvent fields the patterns are matched against


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    # DOTALL: a decoded %0A must not break ".{0,20}", or UNION%0ASELECT slips through.
    return tuple(re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns)


SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "LS-WEB-001", "SQL injection attempt", Severity.HIGH, "T1190",
        _rx(
            r"\bunion\b.{0,20}\bselect\b",               # UNION-based
            r"['\")]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*(?:=|like)",  # ' OR '1'='1
            r"\b(?:or|and)\s+\d+\s*=\s*\d+",             # OR 1=1
            r"\b(?:sleep|benchmark|pg_sleep)\s*\(",      # time-based blind
            r"\bwaitfor\s+delay\b",
            r"\binformation_schema\b",
            r"@@version\b",
            r"\b(?:extractvalue|updatexml|load_file)\s*\(",  # error-based / file read
            r"\binto\s+(?:out|dump)file\b",
            r"['\"]\s*(?:--|;|#(?=\s|&|$))",             # admin'-- / admin'# / stacked query
        ),
    ),
    Signature(
        "LS-WEB-002", "Cross-site scripting (XSS) attempt", Severity.MEDIUM, "T1190",
        _rx(
            r"<\s*script\b",
            r"<[^>]*\bon[a-z]+\s*=",                     # <img src=x onerror=...>
            r"<\s*(?:iframe|svg|object|embed)\b",
            r"javascript\s*:",
            r"\bdocument\.(?:cookie|domain|location)\b",
            r"\b(?:alert|prompt|confirm)\s*\(",
            r"string\.fromcharcode\s*\(",
        ),
    ),
    Signature(
        "LS-WEB-003", "Path traversal / local file inclusion attempt", Severity.HIGH, "T1190",
        _rx(
            r"(?:\.\.[/\\]){2,}",                        # ../../ (one ../ alone is too noisy)
            r"/etc/(?:passwd|shadow|hosts)\b",
            r"\b(?:win|boot)\.ini\b",
            r"/proc/self/",
            r"\b(?:php|file|expect|data)://",
        ),
    ),
    Signature(
        "LS-WEB-006", "Log4Shell exploitation attempt (CVE-2021-44228)", Severity.HIGH, "T1190",
        _rx(r"\$\{jndi:"),
        # Log4j also logged headers, so the payload was usually sent in the User-Agent.
        fields=("path", "user_agent", "referrer"),
    ),
)

# User-Agent fragment -> tool name. Default UAs only: trivially spoofed, so this is a
# low-confidence signal that complements the behavioural detection below.
SCANNER_AGENTS: dict[str, str] = {
    "nikto": "Nikto",
    "sqlmap": "sqlmap",
    "gobuster": "gobuster",
    "dirbuster": "DirBuster",
    "feroxbuster": "feroxbuster",
    "fuzz faster u fool": "ffuf",
    "wfuzz": "wfuzz",
    "nmap scripting engine": "Nmap NSE",
    "masscan": "masscan",
    "zgrab": "zgrab",
    "nuclei": "Nuclei",
    "wpscan": "WPScan",
    "whatweb": "WhatWeb",
    "acunetix": "Acunetix",
    "openvas": "OpenVAS",
}


@dataclass
class WebConfig:
    scan_threshold: int = 20                       # distinct 403/404 paths...
    scan_window: timedelta = timedelta(seconds=60)  # ...within this window
    scan_statuses: frozenset[int] = field(default_factory=lambda: frozenset({403, 404}))


def normalize(path: str) -> str:
    """Decode the request target so encoded payloads match the signatures.

    Decoding twice defeats double encoding (%2527 -> %27 -> '). SQL inline comments
    (/**/) are a classic way to replace spaces and evade filters, so they become spaces.
    MySQL "executable" comments (/*!50000 UNION */) are run by the server, so their
    content is kept instead of being thrown away with the comment.
    """
    decoded = unquote_plus(unquote_plus(path))
    decoded = re.sub(r"/\*!\d*(.*?)\*/", r" \1 ", decoded, flags=re.DOTALL)
    decoded = re.sub(r"/\*.*?\*/", " ", decoded, flags=re.DOTALL)
    return _unwrap_lookups(decoded)


# Log4j "lookups" were abused to hide the word jndi from filters:
#   ${${lower:j}ndi:...}   ${${::-j}${::-n}${::-d}${::-i}:...}   ${${env:X:-j}ndi:...}
# Each innermost ${lower:x} / ${upper:x} / ${anything:-x} is replaced by x until nothing changes.
_LOOKUP = re.compile(r"\$\{(?:(?:lower|upper):|[^${}]*:-)([^${}]*)\}", re.IGNORECASE)


def _unwrap_lookups(text: str) -> str:
    for _ in range(20):          # bounded: nesting deeper than this is not realistic
        new = _LOOKUP.sub(r"\1", text)
        if new == text:
            break
        text = new
    return text


def match_signatures(path: str, user_agent: str = "", referrer: str = "") -> list[tuple[Signature, str]]:
    """Return (signature, field) for every signature that matches one of its fields."""
    values = {"path": path, "user_agent": user_agent, "referrer": referrer}
    hits = []
    for sig in SIGNATURES:
        for fld in sig.fields:
            if values[fld] and any(p.search(normalize(values[fld])) for p in sig.patterns):
                hits.append((sig, fld))
                break
    return hits


def match_scanner(user_agent: str) -> str | None:
    ua = user_agent.lower()
    return next((tool for frag, tool in SCANNER_AGENTS.items() if frag in ua), None)


class _Alerts:
    """Keeps one alert per (rule, source IP) and updates it as more requests match."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], Alert] = {}

    def __contains__(self, key: tuple[str, str]) -> bool:
        return key in self._by_key

    def hit(self, ev: HttpEvent, rule_id: str, title: str, severity: Severity, mitre: str,
            sample: str | None = None, **details) -> None:
        key = (rule_id, ev.source_ip)
        a = self._by_key.get(key)
        if a is None:
            a = self._by_key[key] = Alert(
                rule_id=rule_id, title=title, severity=severity, source_ip=ev.source_ip,
                first_seen=ev.timestamp, last_seen=ev.timestamp, count=0,
                mitre_technique=mitre, details={"samples": [], "status_codes": {}, **details},
            )
        a.last_seen = ev.timestamp
        a.count += 1
        # Plain dict instead of Counter: dataclasses.asdict() cannot rebuild a Counter.
        codes = a.details["status_codes"]
        codes[str(ev.status)] = codes.get(str(ev.status), 0) + 1
        sample = sample or f"{ev.method} {ev.path}".strip()
        if len(a.details["samples"]) < MAX_SAMPLES and sample not in a.details["samples"]:
            a.details["samples"].append(sample)

    def values(self) -> list[Alert]:
        return list(self._by_key.values())


def detect(events: Iterable[HttpEvent], config: WebConfig | None = None,
           rules: Sequence[SigmaRule] = ()) -> list[Alert]:
    """Run the built-in detections, plus any Sigma-style rules loaded by the user."""
    cfg = config or WebConfig()
    alerts = _Alerts()
    # Per IP: recent requests that got a 403/404.
    misses: dict[str, deque[HttpEvent]] = defaultdict(deque)
    scan = ("LS-WEB-004", "Directory / file brute force", Severity.MEDIUM, "T1595.003")

    for ev in sorted(events, key=lambda e: e.timestamp):
        for sig, fld in match_signatures(ev.path, ev.user_agent, ev.referrer):
            # When the payload is in a header, show that header as the evidence.
            sample = None if fld == "path" else f"{ev.method} {ev.path}  [{fld}: {getattr(ev, fld)}]"
            alerts.hit(ev, sig.rule_id, sig.title, sig.severity, sig.mitre_technique, sample=sample)

        for rule in rules:
            if rule.matches(ev):
                alerts.hit(ev, rule.rule_id, rule.title, rule.severity, rule.mitre_technique)

        tool = match_scanner(ev.user_agent)
        if tool:
            alerts.hit(ev, "LS-WEB-005", f"Known scanner User-Agent ({tool})", Severity.LOW,
                       "T1595.002", tool=tool, user_agent=ev.user_agent)

        if ev.status not in cfg.scan_statuses:
            continue
        win = misses[ev.source_ip]
        win.append(ev)
        while win and ev.timestamp - win[0].timestamp > cfg.scan_window:
            win.popleft()

        if ("LS-WEB-004", ev.source_ip) in alerts:
            alerts.hit(ev, *scan)            # scan already flagged: just extend it
        elif len({e.path for e in win}) >= cfg.scan_threshold:
            for e in win:                    # first trigger: the whole window is evidence
                alerts.hit(e, *scan)

    return alerts.values()
