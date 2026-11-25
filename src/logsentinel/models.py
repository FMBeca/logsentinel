"""Core data models shared by parsers and detectors."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AuthEvent:
    """A single normalized SSH authentication event."""

    timestamp: datetime
    host: str
    source_ip: str
    username: str
    success: bool
    invalid_user: bool = False
    raw: str = ""


@dataclass(frozen=True)
class LogLine:
    """Any syslog line (sshd, sudo, cron...), kept whole for keyword-based rules."""

    timestamp: datetime
    host: str
    program: str                 # "sshd", "sudo", "CRON"...
    message: str                 # text after "program[pid]: "
    source_ip: str = "-"         # first remote address found in the message, if any
    raw: str = ""


@dataclass(frozen=True)
class HttpEvent:
    """A single normalized HTTP request from a web server access log."""

    timestamp: datetime          # timezone-aware (access logs include the offset)
    source_ip: str
    method: str
    path: str                    # request target, including the query string
    protocol: str
    status: int
    size: int
    referrer: str = ""
    user_agent: str = ""
    raw: str = ""


@dataclass
class Alert:
    """A detection produced by a detector."""

    rule_id: str
    title: str
    severity: Severity
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    mitre_technique: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d
