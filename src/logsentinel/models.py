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
