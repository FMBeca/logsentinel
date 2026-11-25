"""Parser for OpenSSH entries in Linux auth logs (/var/log/auth.log, /var/log/secure)."""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from logsentinel.models import AuthEvent

# Example lines, in the classic syslog format (no year, no time zone):
# Nov 22 14:01:02 srv1 sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
# Nov 22 14:01:05 srv1 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52213 ssh2
# Nov 22 14:02:00 srv1 sshd[1250]: Accepted publickey for alice from 198.51.100.7 port 40022 ssh2
# Nov 22 14:03:10 srv1 sshd[1260]: Invalid user test from 203.0.113.9 port 50000
# and in RFC 3339, the rsyslog default on current Ubuntu and Debian, and journalctl -o short-iso:
# 2026-11-22T14:01:02.123456+00:00 srv1 sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
TIMESTAMP = (r"(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
             r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
# Since OpenSSH 9.8 the per-connection work runs in separate binaries, so login attempts are
# logged by "sshd-session" (and "sshd-auth" in 10.x) instead of "sshd".
_PREFIX = rf"^{TIMESTAMP}\s(?P<host>\S+)\ssshd(?:-session|-auth)?\[\d+\]:\s"

_PATTERNS = [
    (re.compile(_PREFIX + r"Failed \S+ for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"), False),
    (re.compile(_PREFIX + r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"), True),
    (re.compile(_PREFIX + r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)"), None),
]


def parse_timestamp(ts: str, year: int) -> datetime:
    """Parse a classic ("Nov 22 14:01:02") or RFC 3339 syslog timestamp.

    Classic syslog omits the year, so the caller supplies it; RFC 3339 carries its own.
    Both give the local wall-clock time as written, without a time zone: a log that changed
    format during an OS upgrade holds both kinds of lines, and they must sort together.
    """
    if ts[:4].isdigit():
        ts = ts.replace("Z", "+00:00")
        # Python 3.10 only accepts 3 or 6 fractional digits, and "+0100" without a colon.
        ts = re.sub(r"\.(\d+)", lambda m: "." + (m[1] + "000000")[:6], ts)
        ts = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts)
        return datetime.fromisoformat(ts).replace(tzinfo=None)
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """Parse one log line. Returns None for lines that are not SSH auth events."""
    year = year or datetime.now().year
    line = line.rstrip("\n")
    for pattern, success in _PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        if success is None:
            # "Invalid user" lines duplicate the following "Failed password" line; skip
            # to avoid double counting.
            return None
        return AuthEvent(
            timestamp=parse_timestamp(m["ts"], year),
            host=m["host"],
            source_ip=m["ip"],
            username=m["user"],
            success=success,
            invalid_user=bool(m.groupdict().get("invalid")),
            raw=line,
        )
    return None


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
