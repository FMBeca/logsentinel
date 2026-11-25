"""Generic syslog parser: keeps every line, for keyword-based (Sigma) rules.

The SSH parser only keeps login attempts. Many attack traces live in the other lines:
"Did not receive identification string" (port scanners), crypto errors (exploit attempts),
"maximum authentication attempts exceeded"... This parser keeps them all.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from logsentinel.models import LogLine
from logsentinel.parsers.ssh import TIMESTAMP, parse_timestamp

# Nov 22 14:08:00 srv1 sshd[1600]: Did not receive identification string from 203.0.113.80 port 51515
# 2026-11-22T14:08:00.123456+00:00 srv1 sshd[1600]: ...   (RFC 3339, current Ubuntu / Debian)
_LINE = re.compile(rf"^{TIMESTAMP}\s(?P<host>\S+)\s(?P<prog>[^\s:\[]+)(?:\[\d+\])?:\s?(?P<msg>.*)$")

# Where sshd and PAM put the remote address, most specific first.
_IP = [
    re.compile(r"\bfrom (?:\S+ )?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)(?=\s|$)"),
    re.compile(r"\brhost=(?P<ip>\S+)"),
    re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"),
]


def _source_ip(message: str) -> str:
    for rx in _IP:
        m = rx.search(message)
        if m:
            return m["ip"]
    return "-"


def parse_line(line: str, year: int | None = None) -> LogLine | None:
    line = line.rstrip("\r\n")
    m = _LINE.match(line)
    if not m:
        return None
    return LogLine(
        timestamp=parse_timestamp(m["ts"], year or datetime.now().year),
        host=m["host"],
        program=m["prog"],
        message=m["msg"],
        source_ip=_source_ip(m["msg"]),
        raw=line,
    )


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[LogLine]:
    for line in lines:
        entry = parse_line(line, year)
        if entry is not None:
            yield entry
