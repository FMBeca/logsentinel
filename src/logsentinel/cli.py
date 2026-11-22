"""Command-line interface: logsentinel ssh <logfile> [options]"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta

from logsentinel import __version__
from logsentinel.detectors.bruteforce import BruteForceConfig, detect
from logsentinel.parsers.ssh import parse_lines

_COLORS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;41m"}
_RESET = "\033[0m"


def _print_table(alerts, color: bool) -> None:
    if not alerts:
        print("No threats detected.")
        return
    for a in sorted(alerts, key=lambda x: x.count, reverse=True):
        sev = a.severity.value.upper()
        if color:
            sev = f"{_COLORS[a.severity.value]}{sev}{_RESET}"
        print(f"[{sev}] {a.title}")
        print(f"    IP: {a.source_ip}  attempts: {a.count}  MITRE: {a.mitre_technique}")
        print(f"    {a.first_seen} -> {a.last_seen}")
        print(f"    users: {', '.join(a.details['usernames'][:10])}")
        if "compromised_user" in a.details:
            print(f"    !! login succeeded as '{a.details['compromised_user']}'")
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="logsentinel", description="Detect attacks in log files.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("ssh", help="Analyze an SSH auth log (auth.log / secure)")
    s.add_argument("logfile", help="Path to the log file, or '-' for stdin")
    s.add_argument("--threshold", type=int, default=5, help="Failed attempts to trigger (default 5)")
    s.add_argument("--window", type=int, default=300, help="Window in seconds (default 300)")
    s.add_argument("--year", type=int, help="Year of the log (syslog omits it)")
    s.add_argument("--json", action="store_true", help="Output JSON")
    s.add_argument("--no-color", action="store_true")

    args = p.parse_args(argv)
    cfg = BruteForceConfig(threshold=args.threshold, window=timedelta(seconds=args.window))

    if args.logfile == "-":
        alerts = detect(parse_lines(sys.stdin, args.year), cfg)
    else:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            alerts = detect(parse_lines(fh, args.year), cfg)

    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        _print_table(alerts, color=not args.no_color and sys.stdout.isatty())
    # Non-zero exit code when threats are found makes it usable in scripts/CI.
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
