"""Command-line interface.

    logsentinel ssh <logfile> [options]   # SSH auth logs
    logsentinel web <logfile> [options]   # Apache / Nginx access logs
    logsentinel web <logfile> --rules rules/      # plus Sigma-style YAML rules (ssh too)
    logsentinel web <logfile> --html report.html  # plus a self-contained HTML report
    logsentinel web <logfile> --enrich            # plus AbuseIPDB reputation ($ABUSEIPDB_API_KEY)

Exit codes: 0 no alerts, 1 alerts found, 2 invalid rules, missing API key or unrecognised log format.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import nullcontext
from datetime import timedelta

from logsentinel import __version__, enrich, report, sigma
from logsentinel.detectors import bruteforce, linux, web
from logsentinel.models import Alert, Severity
from logsentinel.parsers import ssh as ssh_parser
from logsentinel.parsers import syslog as syslog_parser
from logsentinel.parsers import web as web_parser
from logsentinel.report import reputation_summary

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
        if "reputation" in d:
            print(f"    reputation: {reputation_summary(d['reputation'])}")
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
    p.add_argument("--html", metavar="FILE", help="Also write a self-contained HTML report to FILE")
    p.add_argument("--rules", action="append", metavar="PATH", default=[],
                   help="Sigma-style YAML rule file or directory; repeatable (needs PyYAML)")
    p.add_argument("--enrich", action="store_true",
                   help=f"Look up public source IPs on AbuseIPDB (API key in ${enrich.ENV_KEY})")


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
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    client = None
    if args.enrich:       # fail fast, before reading a possibly large log
        try:
            client = enrich.AbuseIPDB(os.environ.get(enrich.ENV_KEY, ""))
        except enrich.EnrichError as exc:
            print(f"logsentinel: {exc}", file=sys.stderr)
            return 2

    rules = []
    if args.rules:
        try:
            loaded = sigma.load_rules(args.rules)
        except sigma.RuleError as exc:
            print(f"logsentinel: {exc}", file=sys.stderr)
            return 2
        # A rules folder may hold rules for both log types: keep the ones for this command.
        kind = sigma.LINUX if args.command == "ssh" else sigma.WEB
        rules = [r for r in loaded if r.logsource == kind]
        if len(rules) < len(loaded):
            print(f"logsentinel: skipped {len(loaded) - len(rules)} rule(s) for other log sources", file=sys.stderr)

    with _open(args.logfile) as fh:
        lines = list(fh)

    if args.command == "ssh":
        syslog_lines = list(syslog_parser.parse_lines(lines, args.year))
        recognised = len(syslog_lines)
        events = list(ssh_parser.parse_lines(lines, args.year))
        cfg = bruteforce.BruteForceConfig(threshold=args.threshold, window=timedelta(seconds=args.window))
        alerts = bruteforce.detect(events, cfg)
        if rules:
            alerts += linux.detect(syslog_lines, rules)
    else:
        events = list(web_parser.parse_lines(lines))
        recognised = len(events)
        cfg = web.WebConfig(scan_threshold=args.scan_threshold, scan_window=timedelta(seconds=args.scan_window))
        alerts = web.detect(events, cfg, rules)

    # "No threats detected" on a file that was never understood is a silent false negative.
    nonblank = sum(1 for line in lines if line.strip())
    if nonblank and not recognised:
        expected = "syslog" if args.command == "ssh" else "an access log (combined / common format)"
        print(f"logsentinel: none of the {nonblank} lines look like {expected}: nothing was analysed. "
              "Unsupported log format?", file=sys.stderr)
        return 2
    if args.command == "ssh" and not events:
        print("logsentinel: no sshd login attempts in this log", file=sys.stderr)

    if client is not None:
        enriched = enrich.enrich(alerts, client)
        for warning in client.warnings:
            print(f"logsentinel: {warning}", file=sys.stderr)
        print(f"logsentinel: AbuseIPDB lookups: {client.lookups}, alerts enriched: {enriched} "
              "(private and documentation IPs are never sent)", file=sys.stderr)

    if args.html:
        log_type = "SSH auth log" if args.command == "ssh" else "Web server access log"
        page = report.render_html(alerts, source=args.logfile, log_type=log_type, events=len(events), rules=len(rules))
        with open(args.html, "w", encoding="utf-8") as out:
            out.write(page)
        print(f"HTML report written to {args.html}", file=sys.stderr)

    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        _print_table(alerts, color=not args.no_color and sys.stdout.isatty())
    # Non-zero exit code when threats are found makes it usable in scripts/CI.
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
