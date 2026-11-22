"""Parser for Apache / Nginx access logs in the Combined (or Common) Log Format.

Combined format (Apache ``LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\""``,
and the default ``combined`` format in Nginx):

203.0.113.50 - - [22/Nov/2026:15:02:11 +0000] "GET /admin HTTP/1.1" 404 196 "-" "gobuster/3.6"

The Common Log Format is the same line without the last two quoted fields, so both are accepted.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from logsentinel.models import HttpEvent

# A quoted field. Apache escapes embedded quotes as \" and Nginx as \x22, so we allow
# backslash escapes inside the quotes instead of stopping at the first '"'.
_Q = r'"((?:[^"\\]|\\.)*)"'

_LINE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    rf"{_Q} (?P<status>\d{{3}}) (?P<size>\d+|-)"
    rf"(?: {_Q} {_Q})?"
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str) -> HttpEvent | None:
    """Parse one access-log line. Returns None if the line is not in a supported format."""
    line = line.rstrip("\r\n")   # also tolerate logs copied from Windows (CRLF)
    m = _LINE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], _TS_FORMAT)
    except ValueError:
        return None

    request, referrer, user_agent = m.group(3), m.group(6) or "", m.group(7) or ""
    # A normal request line is "METHOD target PROTOCOL". Malformed requests (scanners,
    # TLS handshakes sent to a plain-HTTP port, "-") are kept, with the raw text as path,
    # because they are often interesting from a security point of view.
    parts = request.split(" ")
    if len(parts) == 3:
        method, path, protocol = parts
    else:
        method, path, protocol = "", request, ""

    return HttpEvent(
        timestamp=ts,
        source_ip=m["ip"],
        method=method,
        path=path,
        protocol=protocol,
        status=int(m["status"]),
        size=0 if m["size"] == "-" else int(m["size"]),
        referrer="" if referrer == "-" else referrer,
        user_agent="" if user_agent == "-" else user_agent,
        raw=line,
    )


def parse_lines(lines: Iterable[str]) -> Iterator[HttpEvent]:
    for line in lines:
        event = parse_line(line)
        if event is not None:
            yield event
