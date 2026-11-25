"""Timestamp formats found on real systems, and the warning for logs that are not understood.

Current Ubuntu and Debian write /var/log/auth.log in RFC 3339 (rsyslog's default), e.g.
    2026-11-23T09:01:01.231312+00:00 host sshd[142]: ...
Before v1.1.1 these lines were silently ignored and the tool reported "No threats detected".
"""
from datetime import datetime

import pytest

from logsentinel import cli
from logsentinel.detectors.bruteforce import detect
from logsentinel.models import Severity
from logsentinel.parsers import ssh, syslog

RFC = "2026-11-23T09:01:0{s}.231312+00:00 srv1 sshd[1201]: Failed password for root from 203.0.113.5 port 5221{s} ssh2"


@pytest.mark.parametrize(
    "ts, expected",
    [
        ("Nov 22 14:01:02", datetime(2026, 11, 22, 14, 1, 2)),             # classic syslog
        ("Nov  2 14:01:02", datetime(2026, 11, 2, 14, 1, 2)),
        ("2026-11-23T09:01:01.231312+00:00", datetime(2026, 11, 23, 9, 1, 1, 231312)),   # rsyslog on Ubuntu
        ("2026-11-23T09:01:01+00:00", datetime(2026, 11, 23, 9, 1, 1)),    # journalctl -o short-iso
        ("2026-11-23T09:01:01Z", datetime(2026, 11, 23, 9, 1, 1)),
        ("2026-11-23T09:01:01.5+0100", datetime(2026, 11, 23, 9, 1, 1, 500000)),        # no colon, 1 digit
        ("2026-11-23T09:01:01.123456789-05:00", datetime(2026, 11, 23, 9, 1, 1, 123456)),  # nanoseconds
    ],
)
def test_timestamps(ts, expected):
    # The RFC 3339 year wins over --year; the wall-clock time is kept as written.
    assert ssh.parse_timestamp(ts, 2026 if ts[0].isalpha() else 1999) == expected


def test_ssh_parser_reads_rfc3339_lines():
    ev = ssh.parse_line(RFC.format(s=2), year=1999)
    assert ev and ev.username == "root" and ev.source_ip == "203.0.113.5" and not ev.success
    assert ev.timestamp.year == 2026


def test_bruteforce_on_rfc3339_log():
    lines = [RFC.format(s=s) for s in range(6)]
    lines.append("2026-11-23T09:01:09.000001+00:00 srv1 sshd[1205]: Accepted password for root from 203.0.113.5 port 1 ssh2")
    (a,) = detect(ssh.parse_lines(lines))
    assert a.severity is Severity.CRITICAL and a.details["compromised_user"] == "root"


def test_log_that_changed_format_during_an_upgrade():
    # The same auth.log holds both formats on the day the OS is upgraded: they must sort together.
    lines = [
        "Nov 23 09:00:58 srv1 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
        "Nov 23 09:00:59 srv1 sshd[1]: Failed password for root from 203.0.113.5 port 2 ssh2",
        *[RFC.format(s=s) for s in range(3)],
    ]
    (a,) = detect(ssh.parse_lines(lines, 2026))
    assert a.count == 5
    assert a.first_seen == datetime(2026, 11, 23, 9, 0, 58)


def test_syslog_parser_reads_rfc3339_lines():
    entry = syslog.parse_line("2026-11-23T09:01:01.286081+00:00 srv1 login: pam_unix(login:session): "
                              "session closed for user alice")
    assert entry and entry.program == "login" and entry.timestamp.year == 2026


# Real lines from Ubuntu 26.04 with OpenSSH 10.2 (host renamed): RFC 3339 timestamps, and the
# attempts are logged by "sshd-session", not "sshd". Both broke detection before v1.1.1.
REAL_OPENSSH_10 = """\
2026-11-25T19:06:58.095519+00:00 srv1 sshd[1165]: Server listening on 0.0.0.0 port 22.
2026-11-25T19:07:53.811978+00:00 srv1 sshd-session[1178]: Invalid user ghost from 127.0.0.1 port 48680
2026-11-25T19:07:56.260748+00:00 srv1 sshd-session[1178]: pam_unix(sshd:auth): check pass; user unknown
2026-11-25T19:07:58.478552+00:00 srv1 sshd-session[1178]: Failed password for invalid user ghost from 127.0.0.1 port 48680 ssh2
2026-11-25T19:08:03.925685+00:00 srv1 sshd-session[1178]: Failed password for invalid user ghost from 127.0.0.1 port 48680 ssh2
2026-11-25T19:08:08.614058+00:00 srv1 sshd-session[1178]: Failed password for invalid user ghost from 127.0.0.1 port 48680 ssh2
2026-11-25T19:08:08.790897+00:00 srv1 sshd-session[1178]: Connection closed by invalid user ghost 127.0.0.1 port 48680 [preauth]
2026-11-25T19:09:10.100000+00:00 srv1 sshd-session[1190]: Failed password for invalid user ghost from 127.0.0.1 port 48700 ssh2
2026-11-25T19:09:15.100000+00:00 srv1 sshd-session[1190]: Failed password for invalid user ghost from 127.0.0.1 port 48700 ssh2
"""


@pytest.mark.parametrize("program", ["sshd", "sshd-session", "sshd-auth"])
def test_openssh_program_names(program):
    line = f"2026-11-25T19:07:58.478552+00:00 srv1 {program}[1178]: Failed password for root from 192.0.2.9 port 1 ssh2"
    assert ssh.parse_line(line) is not None


def test_other_programs_are_not_login_events():
    line = "2026-11-25T19:07:58.478552+00:00 srv1 sshd-keygen[1]: Failed password for root from 192.0.2.9 port 1 ssh2"
    assert ssh.parse_line(line) is None


def test_real_openssh_10_log():
    (a,) = detect(ssh.parse_lines(REAL_OPENSSH_10.splitlines()))
    assert a.source_ip == "127.0.0.1" and a.count == 5
    assert a.details["usernames"] == ["ghost"]


# ------------------------------------------------------------- unrecognised logs

@pytest.mark.parametrize("command", ["ssh", "web"])
def test_unrecognised_log_is_an_error_not_a_clean_result(tmp_path, capsys, command):
    log = tmp_path / "weird.log"
    log.write_text("<134>1 2026-11-23T09:01:01Z srv1 app - - - hello\n{\"json\": true}\n\n", encoding="utf-8")
    assert cli.main([command, str(log)]) == 2
    out, err = capsys.readouterr()
    assert "none of the 2 lines" in err and "Unsupported log format" in err
    assert "No threats detected" not in out


def test_empty_log_is_fine(tmp_path, capsys):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    assert cli.main(["web", str(log)]) == 0
    assert "No threats detected" in capsys.readouterr().out


def test_syslog_without_sshd_events_says_so(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("2026-11-23T09:01:01.231312+00:00 srv1 systemd-logind[142]: New session 3 of user alice.\n",
                   encoding="utf-8")
    assert cli.main(["ssh", str(log)]) == 0
    assert "no sshd login attempts" in capsys.readouterr().err


def test_cli_rfc3339_log_end_to_end(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(RFC.format(s=s) for s in range(6)) + "\n", encoding="utf-8")
    assert cli.main(["ssh", str(log), "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "SSH brute force" in out and "2026-11-23 09:01:00" in out
