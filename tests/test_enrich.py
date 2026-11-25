"""AbuseIPDB enrichment. No test touches the network: responses are simulated."""
import io
import json
import urllib.error
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest

from logsentinel import cli, enrich
from logsentinel.enrich import AbuseIPDB, EnrichError, is_public
from logsentinel.models import Alert, Severity
from logsentinel.report import render_html

ROOT = Path(__file__).resolve().parent.parent
TS = datetime(2026, 11, 22, 15, 0, tzinfo=timezone.utc)
KEY = "test-key-not-real"


def response(ip, score=100, **extra):
    return {"data": {"ipAddress": ip, "abuseConfidenceScore": score, "totalReports": 42,
                     "countryCode": "NL", "isp": "Example Hosting", "usageType": "Data Center",
                     "isTor": False, "lastReportedAt": "2026-11-21T10:00:00+00:00", **extra}}


class FakeAPI:
    """Records every request and answers from a script (dicts or exceptions)."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        answer = self.answers.pop(0) if self.answers else response("x")
        if isinstance(answer, Exception):
            raise answer
        return answer


def http_error(code):
    return urllib.error.HTTPError("https://api.abuseipdb.com/api/v2/check", code, "error", {}, None)


def alert(ip, rule="LS-WEB-001"):
    return Alert(rule_id=rule, title="t", severity=Severity.HIGH, source_ip=ip, first_seen=TS, last_seen=TS,
                 count=1, mitre_technique="T1190", details={})


# ---------------------------------------------------------------- what gets sent

@pytest.mark.parametrize(
    "ip, public",
    [
        ("8.8.8.8", True),
        ("2001:4860:4860::8888", True),
        ("203.0.113.5", False),     # RFC 5737 documentation: the sample logs
        ("192.0.2.44", False),
        ("198.51.100.7", False),
        ("10.0.0.5", False),        # private
        ("192.168.1.10", False),
        ("127.0.0.1", False),       # loopback
        ("2001:db8::1", False),     # IPv6 documentation
        ("fe80::1", False),         # link-local
        ("-", False),               # syslog line without an address
        ("not-an-ip", False),
    ],
)
def test_only_public_ips_are_eligible(ip, public):
    assert is_public(ip) is public


def test_private_ips_never_reach_the_api():
    api = FakeAPI()
    client = AbuseIPDB(KEY, fetch=api)
    assert [client.lookup(ip) for ip in ("10.0.0.5", "203.0.113.5", "-")] == [None, None, None]
    assert api.calls == []


def test_request_format_and_key_in_header_only():
    api = FakeAPI(response("8.8.8.8"))
    AbuseIPDB(KEY, fetch=api, max_age_days=30).lookup("8.8.8.8")
    (url, headers), = api.calls
    assert url == "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30"
    assert headers == {"Key": KEY, "Accept": "application/json"}
    assert KEY not in url                       # URLs end up in proxy logs


def test_response_is_mapped():
    rep = AbuseIPDB(KEY, fetch=FakeAPI(response("8.8.8.8", score=87, isTor=True))).lookup("8.8.8.8")
    assert rep == {"source": "AbuseIPDB", "score": 87, "reports": 42, "country": "NL", "isp": "Example Hosting",
                   "usage": "Data Center", "tor": True, "last_reported": "2026-11-21T10:00:00+00:00"}


def test_each_ip_is_looked_up_once():
    api = FakeAPI(response("8.8.8.8"), response("1.1.1.1"))
    alerts = [alert("8.8.8.8"), alert("8.8.8.8", "LS-WEB-005"), alert("1.1.1.1"), alert("203.0.113.5")]
    client = AbuseIPDB(KEY, fetch=api)
    assert enrich.enrich(alerts, client) == 3
    assert client.lookups == 2 and len(api.calls) == 2
    assert "reputation" not in alerts[3].details


def test_missing_key_is_an_error():
    with pytest.raises(EnrichError, match="ABUSEIPDB_API_KEY"):
        AbuseIPDB("")


# ---------------------------------------------------- failures never stop detection

@pytest.mark.parametrize("code, reason", [(401, "API key rejected"), (403, "API key rejected"), (429, "quota")])
def test_auth_and_quota_errors_stop_further_lookups(code, reason):
    api = FakeAPI(http_error(code))
    client = AbuseIPDB(KEY, fetch=api)
    assert client.lookup("8.8.8.8") is None
    assert client.lookup("1.1.1.1") is None
    assert len(api.calls) == 1                  # no point retrying with a bad key or no quota
    assert reason in client.warnings[0]
    assert KEY not in " ".join(client.warnings)


def test_network_failure_stops_instead_of_timing_out_per_ip():
    api = FakeAPI(urllib.error.URLError("no route to host"))
    client = AbuseIPDB(KEY, fetch=api)
    for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
        assert client.lookup(ip) is None
    assert len(api.calls) == 1
    assert "cannot reach the API" in client.warnings[0]


def test_server_error_only_skips_that_ip():
    api = FakeAPI(http_error(500), response("1.1.1.1"))
    client = AbuseIPDB(KEY, fetch=api)
    assert client.lookup("8.8.8.8") is None
    assert client.lookup("1.1.1.1")["score"] == 100
    assert "HTTP 500" in client.warnings[0]


@pytest.mark.parametrize("bad", [{}, {"data": None}, {"data": {"abuseConfidenceScore": "high"}}])
def test_unexpected_responses_are_skipped(bad):
    client = AbuseIPDB(KEY, fetch=FakeAPI(bad))
    assert client.lookup("8.8.8.8") is None
    assert "unexpected response" in client.warnings[0]


def test_default_http_fetch(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen.update(url=req.full_url, key=req.get_header("Key"), timeout=timeout)
        return io.BytesIO(json.dumps(response("8.8.8.8")).encode())

    monkeypatch.setattr(enrich.urllib.request, "urlopen", fake_urlopen)
    assert AbuseIPDB(KEY).lookup("8.8.8.8")["isp"] == "Example Hosting"
    assert seen == {"url": enrich.API_URL + "?ipAddress=8.8.8.8&maxAgeInDays=90", "key": KEY, "timeout": enrich.TIMEOUT}


# ---------------------------------------------------------------- output

def test_reputation_in_html_report_is_escaped():
    a = alert("8.8.8.8")
    a.details["reputation"] = AbuseIPDB(KEY, fetch=FakeAPI(response("8.8.8.8", isp="<script>alert(1)</script>"))).lookup(
        "8.8.8.8")
    html = render_html([a], source="x.log", log_type="t", events=1)
    tags = []

    class P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            tags.append(tag)

    P().feed(html)
    assert "script" not in tags
    assert "100/100 abuse score" in html and "&lt;script&gt;" in html


def test_cli_without_key_exits_2(monkeypatch, capsys):
    monkeypatch.delenv(enrich.ENV_KEY, raising=False)
    assert cli.main(["web", str(ROOT / "samples" / "access.log"), "--enrich"]) == 2
    assert "ABUSEIPDB_API_KEY" in capsys.readouterr().err


def test_cli_sample_logs_send_nothing(monkeypatch, capsys):
    # The samples only use documentation IPs: --enrich must not make a single request.
    monkeypatch.setenv(enrich.ENV_KEY, KEY)
    monkeypatch.setattr(enrich, "_http_fetch", lambda *a: pytest.fail("network call"))
    assert cli.main(["web", str(ROOT / "samples" / "access.log"), "--enrich", "--no-color"]) == 1
    assert "lookups: 0" in capsys.readouterr().err


def test_cli_shows_reputation(monkeypatch, capsys):
    monkeypatch.setenv(enrich.ENV_KEY, KEY)
    monkeypatch.setattr(enrich, "is_public", lambda ip: ip == "203.0.113.5")   # pretend the sample IP is public
    monkeypatch.setattr(enrich, "_http_fetch", FakeAPI(response("203.0.113.5", score=100)))
    cli.main(["ssh", str(ROOT / "samples" / "auth.log"), "--year", "2026", "--enrich", "--no-color"])
    out, err = capsys.readouterr()
    assert "reputation: 100/100 abuse score · 42 reports · NL · Example Hosting (AbuseIPDB)" in out
    assert "lookups: 1, alerts enriched: 1" in err
