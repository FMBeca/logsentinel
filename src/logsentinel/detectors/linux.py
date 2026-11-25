"""Apply keyword-based Sigma rules to Linux auth / syslog lines.

The built-in SSH detector reasons about login attempts over time; these rules catch single
lines that matter on their own: scanners that never finish the SSH handshake, crypto errors
caused by exploit attempts, and anything else a rule author adds.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

from logsentinel.models import Alert, LogLine

if TYPE_CHECKING:
    from logsentinel.sigma import SigmaRule

MAX_SAMPLES = 5


def detect(lines: Iterable[LogLine], rules: Sequence[SigmaRule]) -> list[Alert]:
    """One alert per (rule, source IP); lines without an address share the IP "-"."""
    alerts: dict[tuple[str, str], Alert] = {}
    if not rules:
        return []
    for line in sorted(lines, key=lambda x: x.timestamp):
        for rule in rules:
            if not rule.matches(line):
                continue
            key = (rule.rule_id, line.source_ip)
            a = alerts.get(key)
            if a is None:
                a = alerts[key] = Alert(
                    rule_id=rule.rule_id, title=rule.title, severity=rule.severity,
                    source_ip=line.source_ip, first_seen=line.timestamp, last_seen=line.timestamp,
                    count=0, mitre_technique=rule.mitre_technique, details={"samples": []},
                )
            a.last_seen = line.timestamp
            a.count += 1
            sample = f"{line.program}: {line.message}"
            if len(a.details["samples"]) < MAX_SAMPLES and sample not in a.details["samples"]:
                a.details["samples"].append(sample)
    return list(alerts.values())
