from datetime import timedelta
from pathlib import Path

from logsentinel.cli import main
from logsentinel.detectors.bruteforce import BruteForceConfig, detect
from logsentinel.models import Severity
from logsentinel.parsers.ssh import parse_line, parse_lines

SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"


def test_parse_failed_password():
    ev = parse_line("Nov 22 14:01:02 srv1 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2", 2026)
    assert ev and ev.username == "root" and ev.source_ip == "203.0.113.5"
    assert not ev.success and not ev.invalid_user
    assert ev.timestamp.year == 2026


def test_parse_invalid_user():
    ev = parse_line("Nov  2 14:05:00 srv1 sshd[1]: Failed password for invalid user admin from 192.0.2.44 port 1 ssh2", 2026)
    assert ev and ev.invalid_user and ev.username == "admin"


def test_parse_accepted_and_ignores_noise():
    assert parse_line("Nov 22 14:00:01 srv1 sshd[1]: Accepted publickey for alice from 198.51.100.7 port 1 ssh2").success
    assert parse_line("Nov 22 14:07:00 srv1 CRON[1]: session opened for user root") is None


def _alerts():
    with SAMPLE.open() as f:
        return {a.source_ip: a for a in detect(parse_lines(f, 2026))}


def test_detects_bruteforce_then_compromise():
    a = _alerts()["203.0.113.5"]
    assert a.severity is Severity.CRITICAL
    assert a.details["compromised_user"] == "root"
    assert a.mitre_technique == "T1110.001"


def test_detects_password_spraying():
    a = _alerts()["192.0.2.44"]
    assert a.mitre_technique == "T1110.003" and a.severity is Severity.HIGH


def test_no_false_positive_for_single_typo():
    assert "198.51.100.20" not in _alerts()


def test_window_expiry():
    with SAMPLE.open() as f:
        cfg = BruteForceConfig(threshold=5, window=timedelta(seconds=5))
        assert detect(parse_lines(f, 2026), cfg) == []


def test_cli_exit_code(capsys):
    assert main(["ssh", str(SAMPLE), "--year", "2026", "--json"]) == 1
    assert "LS-SSH-001" in capsys.readouterr().out
