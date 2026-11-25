from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest

from logsentinel import cli
from logsentinel.models import Alert, Severity
from logsentinel.report import render_html

ROOT = Path(__file__).resolve().parent.parent
TS = datetime(2026, 11, 22, 15, 0, tzinfo=timezone.utc)


def alert(**kw):
    base = dict(rule_id="LS-WEB-001", title="SQL injection attempt", severity=Severity.HIGH,
                source_ip="203.0.113.77", first_seen=TS, last_seen=TS, count=3,
                mitre_technique="T1190", details={})
    return Alert(**{**base, **kw})


def render(alerts, **kw):
    opts = {"source": "access.log", "log_type": "Web server access log", "events": 10, "generated": TS, **kw}
    return render_html(alerts, **opts)


class _Tags(HTMLParser):
    """Collects every element and attribute the browser would actually create."""

    def __init__(self):
        super().__init__()
        self.tags, self.attrs = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [name for name, _ in attrs]


def parsed(html):
    p = _Tags()
    p.feed(html)
    return p


# Payloads an attacker can put in a request that ends up in the log, and so in the report.
PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    "</code></li></ul><iframe src=javascript:alert(1)>",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_log_content_cannot_inject_html(payload):
    a = alert(
        rule_id=payload, title=payload, source_ip=payload, mitre_technique=payload,
        details={"samples": [f"GET /search?q={payload}"], "user_agent": payload,
                 "usernames": [payload], "compromised_user": payload, "status_codes": {payload: 1}},
    )
    html = render([a], source=payload)
    p = parsed(html)
    assert not {"script", "img", "svg", "iframe"} & set(p.tags)
    assert not [name for name in p.attrs if name.startswith("on")]
    assert "&lt;" in html                                   # shown as text instead


def test_csp_forbids_scripts_and_remote_loads():
    html = render([alert()])
    assert "default-src 'none'" in html
    assert "script-src" not in html                         # nothing re-allows scripts
    assert "<script" not in html and "http://" not in html


@pytest.mark.parametrize(
    "technique, url",
    [
        ("T1190", "https://attack.mitre.org/techniques/T1190/"),
        ("T1110.003", "https://attack.mitre.org/techniques/T1110/003/"),
    ],
)
def test_mitre_links(technique, url):
    assert f'href="{url}"' in render([alert(mitre_technique=technique)])


def test_multiple_techniques_from_sigma_rules_are_all_linked():
    html = render([alert(mitre_technique="T1190, T1505.003")])
    assert "techniques/T1190/" in html and "techniques/T1505/003/" in html


def test_summary_counts_and_order():
    alerts = [
        alert(severity=Severity.LOW, title="Low one", source_ip="192.0.2.1"),
        alert(severity=Severity.CRITICAL, title="Critical one", source_ip="192.0.2.2"),
        alert(severity=Severity.HIGH, title="High one", source_ip="192.0.2.2"),
    ]
    html = render(alerts)
    assert '<div class="tile critical"><span>1</span>' in html
    assert '<div class="tile medium"><span>0</span>' in html
    assert '<div class="tile"><span>2</span>Source IPs' in html
    assert html.index("Critical one") < html.index("High one") < html.index("Low one")
    assert "Alerts (3)" in html


def test_compromise_is_highlighted():
    html = render([alert(severity=Severity.CRITICAL, details={"compromised_user": "root"})])
    assert 'class="warn"' in html and "<code>root</code>" in html


def test_empty_report():
    html = render([])
    assert "No threats detected." in html and "Alerts (0)" in html


def test_custom_rule_count_only_when_used():
    assert "Custom rules" not in render([])
    assert "Custom rules" in render([], rules=2)


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["ssh", str(ROOT / "samples" / "auth.log"), "--year", "2026"], "Successful login after SSH brute force"),
        (["web", str(ROOT / "samples" / "access.log")], "Log4Shell exploitation attempt"),
    ],
)
def test_cli_writes_html_report(tmp_path, capsys, argv, expected):
    out = tmp_path / "report.html"
    assert cli.main([*argv, "--html", str(out)]) == 1        # exit code unchanged
    html = out.read_text(encoding="utf-8")
    assert expected in html
    assert "HTML report written" in capsys.readouterr().err
    assert "script" not in parsed(html).tags
