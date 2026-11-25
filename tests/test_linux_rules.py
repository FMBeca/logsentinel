from pathlib import Path

import pytest

from logsentinel import cli
from logsentinel.detectors import linux
from logsentinel.parsers.syslog import parse_line, parse_lines
from logsentinel.sigma import LINUX, WEB, RuleError, load_rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "auth.log"
LINUX_RULES = ROOT / "rules" / "linux"


def rule(detection, service="sshd", **extra):
    data = {"title": "test", "logsource": {"product": "linux", "service": service}, "detection": detection, **extra}
    return load_rule(data)


def line(text):
    entry = parse_line(text, 2026)
    assert entry is not None
    return entry


# ------------------------------------------------------------------------ parser

@pytest.mark.parametrize(
    "text, program, ip",
    [
        ("Nov 22 14:08:00 srv1 sshd[1600]: Did not receive identification string from 203.0.113.80 port 51515",
         "sshd", "203.0.113.80"),
        ("Nov 22 14:10:00 srv1 sshd[1800]: ssh_dispatch_run_fatal: Connection from 192.0.2.66 port 50122: "
         "Corrupted MAC on input. [preauth]", "sshd", "192.0.2.66"),
        ("Nov  2 09:00:00 srv1 sshd[9]: Connection closed by authenticating user root 192.0.2.7 port 5 [preauth]",
         "sshd", "192.0.2.7"),
        ("Nov 22 14:00:00 srv1 sshd[9]: Accepted publickey for alice from 2001:db8::7 port 40022 ssh2",
         "sshd", "2001:db8::7"),
        ("Nov 22 14:00:00 srv1 sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1000 rhost=192.0.2.8",
         "sudo", "192.0.2.8"),
        ("Nov 22 14:07:00 srv1 CRON[1500]: pam_unix(cron:session): session opened for user root", "CRON", "-"),
    ],
)
def test_syslog_parser_keeps_every_line(text, program, ip):
    entry = line(text)
    assert (entry.program, entry.source_ip, entry.raw) == (program, ip, text)
    assert entry.timestamp.year == 2026


def test_syslog_parser_skips_non_syslog_lines():
    assert parse_line("not a syslog line") is None
    assert parse_line("") is None


# ------------------------------------------------------------------------ rules

@pytest.mark.parametrize("service", ["sshd", "auth"])
def test_linux_logsource_variants(service):
    assert rule({"k": ["x"], "condition": "k"}, service=service).logsource == LINUX


def test_web_rules_are_tagged_web():
    r = load_rule({"title": "w", "logsource": {"category": "webserver"},
                   "detection": {"s": {"cs-method": "GET"}, "condition": "s"}})
    assert r.logsource == WEB


def test_keywords_are_case_insensitive_substrings():
    r = rule({"k": ["corrupted mac on input"], "condition": "k"})
    assert r.matches(line("Nov 22 14:10:00 srv1 sshd[1]: ssh_dispatch_run_fatal: Corrupted MAC on input. [preauth]"))
    assert not r.matches(line("Nov 22 14:10:00 srv1 sshd[1]: Received disconnect from 198.51.100.7 port 1:11: bye"))


def test_keyword_conditions_combine():
    r = rule({"scan": ["identification string"], "allowed": ["from 198.51.100."], "condition": "scan and not allowed"})
    assert r.matches(line("Nov 22 14:00:00 srv1 sshd[1]: Did not receive identification string from 203.0.113.9 port 1"))
    assert not r.matches(line("Nov 22 14:00:00 srv1 sshd[1]: Did not receive identification string from 198.51.100.3 port 1"))


@pytest.mark.parametrize(
    "logsource",
    [{"product": "linux"}, {"product": "linux", "service": "auditd"}, {"product": "windows", "service": "security"}],
)
def test_unsupported_linux_log_sources(logsource):
    with pytest.raises(RuleError, match="supported log sources"):
        load_rule({"title": "x", "logsource": logsource, "detection": {"k": ["a"], "condition": "k"}})


def test_linux_rules_reject_field_selections():
    # Syslog lines have no standard fields: a field rule would load and never fire.
    with pytest.raises(RuleError, match="keyword lists only"):
        rule({"s": {"cs-method": "GET"}, "condition": "s"})


# --------------------------------------------------------------- detector and CLI

def _sample_alerts():
    pytest.importorskip("yaml")
    with SAMPLE.open(encoding="utf-8") as fh:
        return linux.detect(parse_lines(fh, 2026), load_rules([LINUX_RULES]))


def test_example_rules_fire_on_the_sample_log():
    found = {(a.title, a.source_ip, a.count) for a in _sample_alerts()}
    assert found == {
        ("SSH port scan or banner grab", "203.0.113.80", 3),
        ("Suspicious OpenSSH protocol or crypto error", "192.0.2.66", 2),
    }


def test_example_rules_ignore_normal_sshd_activity():
    pytest.importorskip("yaml")
    rules = load_rules([LINUX_RULES])
    benign = [
        "Nov 22 14:00:01 srv1 sshd[1100]: Accepted publickey for alice from 198.51.100.7 port 40022 ssh2",
        "Nov 22 14:11:00 srv1 sshd[1100]: Received disconnect from 198.51.100.7 port 40022:11: disconnected by user",
        "Nov 22 14:11:01 srv1 sshd[1100]: Disconnected from user alice 198.51.100.7 port 40022",
        "Nov 22 14:11:02 srv1 sshd[1100]: pam_unix(sshd:session): session closed for user alice",
        "Nov 22 14:11:03 srv1 sshd[900]: Server listening on 0.0.0.0 port 22.",
        "Nov 22 14:01:02 srv1 sshd[1201]: Failed password for root from 203.0.113.5 port 52211 ssh2",
    ]
    assert [(t, r.title) for t in benign for r in rules if r.matches(line(t))] == []


def test_samples_are_kept_per_alert():
    scan = next(a for a in _sample_alerts() if a.source_ip == "203.0.113.80")
    assert scan.details["samples"][0].startswith("sshd: Did not receive identification string")
    assert scan.mitre_technique == "T1595"


def test_no_rules_means_no_alerts():
    with SAMPLE.open(encoding="utf-8") as fh:
        assert linux.detect(parse_lines(fh, 2026), []) == []


def test_cli_ssh_rules_from_mixed_folder(capsys):
    pytest.importorskip("yaml")
    code = cli.main(["ssh", str(SAMPLE), "--year", "2026", "--rules", str(ROOT / "rules"), "--no-color"])
    captured = capsys.readouterr()
    assert code == 1
    assert "SSH port scan or banner grab" in captured.out
    assert "Successful login after SSH brute force" in captured.out     # built-in detection still runs
    assert "skipped 2 rule(s) for other log sources" in captured.err   # the web rules


def test_cli_web_skips_linux_rules(capsys):
    pytest.importorskip("yaml")
    cli.main(["web", str(ROOT / "samples" / "access.log"), "--rules", str(ROOT / "rules"), "--no-color"])
    captured = capsys.readouterr()
    assert "Web shell access attempt" in captured.out
    assert "SSH port scan" not in captured.out
    assert "skipped 2 rule(s)" in captured.err
