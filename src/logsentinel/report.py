"""Self-contained HTML report: one file, no JavaScript, no external resources.

Security note: alerts carry attacker-controlled text (paths, User-Agents, usernames). A report
that pasted it into HTML as-is would run the attacker's XSS payload in the analyst's browser
(stored XSS through the logs). So every value goes through html.escape(), and a strict
Content-Security-Policy forbids scripts and remote loads as a second layer of defence.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from html import escape

from logsentinel import __version__
from logsentinel.models import Alert, Severity

# No scripts, no remote resources, no forms: only the inline stylesheet may load.
_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
_ORDER = list(reversed(Severity))            # critical, high, medium, low
_RANK = {s: i for i, s in enumerate(Severity)}
_TECHNIQUE = re.compile(r"T(\d{4})(?:\.(\d{3}))?")


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _techniques(text: str) -> list[str]:
    return [t.strip() for t in text.split(",") if _TECHNIQUE.fullmatch(t.strip())]


def _mitre_link(tech: str) -> str:
    m = _TECHNIQUE.fullmatch(tech)
    url = f"https://attack.mitre.org/techniques/T{m.group(1)}/" + (f"{m.group(2)}/" if m.group(2) else "")
    return f'<a href="{_e(url)}" rel="noopener noreferrer">{_e(tech)}</a>'


def _mitre_cell(text: str) -> str:
    links = [_mitre_link(t) for t in _techniques(text)]
    return ", ".join(links) if links else _e(text)


def _alert(a: Alert) -> str:
    d = a.details
    rows = [
        ("Source IP", f"<code>{_e(a.source_ip)}</code>"),
        ("Events", _e(a.count)),
        ("First seen", _e(a.first_seen)),
        ("Last seen", _e(a.last_seen)),
        ("MITRE ATT&amp;CK", _mitre_cell(a.mitre_technique)),
    ]
    if d.get("usernames"):
        rows.append(("Users", _e(", ".join(d["usernames"]))))
    if d.get("status_codes"):
        codes = sorted(d["status_codes"].items())
        rows.append(("Status", ", ".join(f"{_e(k)} &times; {_e(v)}" for k, v in codes)))
    if d.get("user_agent"):
        rows.append(("User-Agent", f"<code>{_e(d['user_agent'])}</code>"))
    grid = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)

    warn = ""
    if d.get("compromised_user"):
        warn = f'<p class="warn">Login succeeded as <code>{_e(d["compromised_user"])}</code> from this IP.</p>'
    samples = ""
    if d.get("samples"):
        items = "".join(f"<li><code>{_e(s)}</code></li>" for s in d["samples"])
        samples = f'<div class="samples"><h4>Evidence</h4><ul>{items}</ul></div>'

    sev = a.severity.value
    return (
        f'<article class="alert sev-{sev}">'
        f'<header><span class="badge {sev}">{_e(sev.upper())}</span>'
        f"<h3>{_e(a.title)}</h3><code class=\"rule\">{_e(a.rule_id)}</code></header>"
        f"{warn}<dl>{grid}</dl>{samples}</article>"
    )


def render_html(alerts: Sequence[Alert], *, source: str, log_type: str, events: int,
                rules: int = 0, generated: datetime | None = None) -> str:
    """Build the report. ``source`` is the analysed file, ``log_type`` e.g. "SSH auth log"."""
    generated = generated or datetime.now(timezone.utc)
    ordered = sorted(alerts, key=lambda a: (_RANK[a.severity], a.count), reverse=True)
    counts = Counter(a.severity for a in alerts)
    techniques = Counter(t for a in alerts for t in _techniques(a.mitre_technique))
    ips = {a.source_ip for a in alerts}

    tiles = "".join(
        f'<div class="tile {s.value}"><span>{counts.get(s, 0)}</span>{s.value.capitalize()}</div>' for s in _ORDER
    ) + f'<div class="tile"><span>{len(ips)}</span>Source IPs</div>'

    if techniques:
        chips = "".join(f"<li>{_mitre_link(t)} <small>&times;{n}</small></li>" for t, n in sorted(techniques.items()))
        mitre = f'<section><h2>MITRE ATT&amp;CK techniques</h2><ul class="chips">{chips}</ul></section>'
    else:
        mitre = ""

    body = "".join(_alert(a) for a in ordered) if ordered else '<p class="empty">No threats detected.</p>'
    meta = [
        ("File", f"<code>{_e(source)}</code>"),
        ("Log type", _e(log_type)),
        ("Events parsed", _e(events)),
        ("Generated", _e(generated.strftime("%Y-%m-%d %H:%M:%S %Z").strip())),
    ]
    if rules:
        meta.insert(3, ("Custom rules", _e(rules)))
    meta_html = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in meta)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="referrer" content="no-referrer">
<title>LogSentinel report</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header class="top">
<h1>LogSentinel report</h1>
<dl class="meta">{meta_html}</dl>
</header>
<section><h2>Summary</h2><div class="tiles">{tiles}</div></section>
{mitre}
<section><h2>Alerts ({len(ordered)})</h2>{body}</section>
<footer>
<p>Signature hits are attempts, not proof of compromise: check the status codes and the evidence
before escalating. All values come from the log and are shown as plain text.</p>
<p>Generated by LogSentinel {_e(__version__)}</p>
</footer>
</main>
</body>
</html>
"""


_CSS = """
:root {
  --bg: #f6f8fa; --card: #ffffff; --text: #1f2328; --muted: #59636e; --border: #d1d9e0;
  --code: #eff2f5; --link: #0969da;
  --critical: #a40e26; --high: #cf222e; --medium: #9a6700; --low: #0969da;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --card: #151b23; --text: #e6edf3; --muted: #9198a1; --border: #3d444d;
    --code: #212830; --link: #4493f8;
    --critical: #ff7b72; --high: #f85149; --medium: #d29922; --low: #58a6ff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
main { max-width: 1000px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 26px; margin: 0 0 12px; }
h2 { font-size: 18px; margin: 32px 0 12px; }
h3 { font-size: 16px; margin: 0; flex: 1; }
h4 { font-size: 13px; margin: 12px 0 4px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
a { color: var(--link); }
code { font: 13px/1.4 ui-monospace, Consolas, "SFMono-Regular", monospace; background: var(--code);
  padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 28px; margin: 0; }
.meta dt { font-size: 12px; color: var(--muted); }
.meta dd { margin: 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; }
.tile { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px;
  color: var(--muted); }
.tile span { display: block; font-size: 28px; font-weight: 600; color: var(--text); }
.tile.critical span { color: var(--critical); } .tile.high span { color: var(--high); }
.tile.medium span { color: var(--medium); } .tile.low span { color: var(--low); }
.chips { list-style: none; display: flex; flex-wrap: wrap; gap: 8px; padding: 0; margin: 0; }
.chips li { background: var(--card); border: 1px solid var(--border); border-radius: 999px; padding: 2px 12px; }
.chips small { color: var(--muted); }
.alert { background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--muted);
  border-radius: 8px; padding: 16px; margin-bottom: 12px; }
.alert.sev-critical { border-left-color: var(--critical); } .alert.sev-high { border-left-color: var(--high); }
.alert.sev-medium { border-left-color: var(--medium); } .alert.sev-low { border-left-color: var(--low); }
.alert header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.rule { font-size: 12px; color: var(--muted); }
.badge { font-size: 11px; font-weight: 700; letter-spacing: .05em; padding: 2px 8px; border-radius: 4px;
  color: #fff; background: var(--muted); }
.badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
.badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
@media (prefers-color-scheme: dark) { .badge { color: #0d1117; } }
.alert dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 12px 0 0; }
.alert dt { color: var(--muted); }
.alert dd { margin: 0; min-width: 0; }
.warn { margin: 10px 0 0; padding: 8px 12px; border-radius: 6px; font-weight: 600;
  color: var(--critical); border: 1px solid var(--critical); }
.samples ul { margin: 0; padding-left: 18px; }
.samples li { margin: 2px 0; }
.empty { color: var(--muted); }
footer { margin-top: 32px; color: var(--muted); font-size: 13px; border-top: 1px solid var(--border); }
@media (max-width: 600px) { .alert dl { grid-template-columns: 1fr; } .alert dt { margin-top: 6px; } }
@media print { body { background: #fff; } .alert { break-inside: avoid; } }
"""
