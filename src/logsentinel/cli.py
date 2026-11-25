"""Command-line interface.

    logsentinel ssh <logfile> [options]   # SSH auth logs
    logsentinel web <logfile> [options]   # Apache / Nginx access logs
    logsentinel web <logfile> --rules rules/web   # plus Sigma-style YAML rules

Exit codes: 0 no alerts, 1 alerts found, 2 invalid rules.
"""
from __future__ import annotations

import argparse
import json
import sys
from contextlib import nullcontext
from datetime import timedelta

from logsentinel import __version__, sigma
from logsentinel.detectors import bruteforce, web
from logsentinel.models import Alert, Severity
from logsentinel.parsers import ssh as ssh_parser
from logsentinel.parsers import web as web_parser

_COLORS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;41m"}
_RESET = "\033[0m"
_RANK = {s: i for i, s in enumerate(Severity)}


def _print_table(alerts: list[Alert], color: bool) -> None:
    if not alerts:
        print("No threats detected.")
        return
    # Most severe first, then the noisiest source.
    for a in sorted(alerts, key=lambda x: (_RANK[x.severity], x.count), reverse=True):
        sev = a.severity.value.upper()
        if color:
            sev = f"{_COLORS[a.severity.value]}{sev}{_RESET}"
        print(f"[{sev}] {a.title}  ({a.rule_id})")
        print(f"    IP: {a.source_ip}  events: {a.count}  MITRE: {a.mitre_technique}")
        print(f"    {a.first_seen} -> {a.last_seen}")
        d = a.details
        if "usernames" in d:
            print(f"    users: {', '.join(d['usernames'][:10])}")
        if "compromised_user" in d:
            print(f"    !! login succeeded as '{d['compromised_user']}'")
        if d.get("status_codes"):
            print("    status: " + ", ".join(f"{k}x{v}" for k, v in sorted(d["status_codes"].items())))
        if "user_agent" in d:
            print(f"    user-agent: {d['user_agent']}")
        for s in d.get("samples", []):
            print(f"    > {s[:120]}")
        print()


def _open(path: str):
    if path == "-":
        return nullcontext(sys.stdin)
    return open(path, encoding="utf-8", errors="replace")


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("logfile", help="Path to the log file, or '-' for stdin")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--no-color", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logsentinel", description="Detect attacks in log files.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("ssh", help="Analyze an SSH auth log (auth.log / secure)")
    _add_common(s)
    s.add_argument("--threshold", type=int, default=5, help="Failed attempts to trigger (default 5)")
    s.add_argument("--window", type=int, default=300, help="Window in seconds (default 300)")
    s.add_argument("--year", type=int, help="Year of the log (syslog omits it)")

    w = sub.add_parser("web", help="Analyze an Apache/Nginx access log (combined format)")
    _add_common(w)
    w.add_argument("--scan-threshold", type=int, default=20,
                   help="Distinct 403/404 paths to flag directory brute force (default 20)")
    w.add_argument("--scan-window", type=int, default=60, help="Window in seconds (default 60)")
    w.add_argument("--rules", action="append", metavar="PATH", default=[],
                   help="Sigma-style YAML rule file or directory; repeatable (needs PyYAML)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    rules = []
    if getattr(args, "rules", None):
        try:
            rules = sigma.load_rules(args.rules)
        except sigma.RuleError as exc:
            print(f"logsentinel: {exc}", file=sys.stderr)
            return 2

    with _open(args.logfile) as fh:
        if args.command == "ssh":
            cfg = bruteforce.BruteForceConfig(threshold=args.threshold, window=timedelta(seconds=args.window))
            alerts = bruteforce.detect(ssh_parser.parse_lines(fh, args.year), cfg)
        else:
            cfg = web.WebConfig(scan_threshold=args.scan_threshold, scan_window=timedelta(seconds=args.scan_window))
            alerts = web.detect(web_parser.parse_lines(fh), cfg, rules)

    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        _print_table(alerts, color=not args.no_color and sys.stdout.isatty())
    # Non-zero exit code when threats are found makes it usable in scripts/CI.
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
