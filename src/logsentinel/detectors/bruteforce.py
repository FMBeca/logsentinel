"""SSH brute-force detection using a sliding time window per source IP.

MITRE ATT&CK: T1110 - Brute Force (T1110.001 Password Guessing,
T1110.003 Password Spraying), plus T1078 - Valid Accounts when a login then succeeds.
"""
from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta

from logsentinel.models import Alert, AuthEvent, Severity


@dataclass
class BruteForceConfig:
    threshold: int = 5                 # failed attempts...
    window: timedelta = timedelta(minutes=5)  # ...within this window
    spray_users: int = 3               # distinct usernames => password spraying


def detect(events: Iterable[AuthEvent], config: BruteForceConfig | None = None) -> list[Alert]:
    cfg = config or BruteForceConfig()
    windows: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: dict[str, Alert] = {}
    compromised: set[str] = set()

    for ev in sorted(events, key=lambda e: e.timestamp):
        ip = ev.source_ip

        if ev.success:
            # A success right after an active brute-force burst is the most critical signal.
            if ip in alerts and ip not in compromised:
                compromised.add(ip)
                a = alerts[ip]
                a.severity = Severity.CRITICAL
                a.title = "Successful login after SSH brute force"
                # Keep the brute-force technique and add Valid Accounts: the attacker now
                # holds working credentials, which is what the responder must act on.
                a.mitre_technique = f"{a.mitre_technique}, T1078"
                a.details["compromised_user"] = ev.username
                a.details["success_time"] = ev.timestamp.isoformat()
            continue

        win = windows[ip]
        win.append(ev)
        while win and ev.timestamp - win[0].timestamp > cfg.window:
            win.popleft()

        if len(win) < cfg.threshold:
            continue

        users = {e.username for e in win}
        spraying = len(users) >= cfg.spray_users
        if ip not in alerts:
            alerts[ip] = Alert(
                rule_id="LS-SSH-001",
                title="SSH password spraying" if spraying else "SSH brute force",
                severity=Severity.HIGH if spraying else Severity.MEDIUM,
                source_ip=ip,
                first_seen=win[0].timestamp,
                last_seen=ev.timestamp,
                count=len(win),
                mitre_technique="T1110.003" if spraying else "T1110.001",
                details={"usernames": sorted(users)},
            )
        else:
            a = alerts[ip]
            a.last_seen = ev.timestamp
            a.count += 1
            a.details["usernames"] = sorted(set(a.details["usernames"]) | users)

    return list(alerts.values())
