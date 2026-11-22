# 🛡️ LogSentinel

![CI](https://github.com/FMBeca/logsentinel/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**LogSentinel** is a lightweight, dependency-free CLI that detects attacks in Linux log files
and maps every alert to **MITRE ATT&CK**. It's built to show how SOC detection logic works
under the hood — the same ideas SIEMs like Splunk, Elastic or Wazuh apply at scale.

## Features

| Detection | Rule | MITRE ATT&CK | Status |
|---|---|---|---|
| SSH brute force (one user, many attempts) | LS-SSH-001 | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | ✅ |
| SSH password spraying (many users) | LS-SSH-001 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | ✅ |
| Successful login after brute force (likely compromise) | LS-SSH-001 | [T1078](https://attack.mitre.org/techniques/T1078/) | ✅ |
| Web attacks (SQLi, XSS, directory scanning) | LS-WEB-* | T1190, T1595 | 🚧 planned |
| YAML-configurable rules | — | — | 🚧 planned |

## Quick start

```bash
git clone https://github.com/FMBeca/logsentinel.git
cd logsentinel
pip install -e .
logsentinel ssh samples/auth.log --year 2026
```

Example output:

```
[CRITICAL] Successful login after SSH brute force
    IP: 203.0.113.5  attempts: 6  MITRE: T1110.001
    2026-11-22 14:01:02 -> 2026-11-22 14:01:12
    users: root
    !! login succeeded as 'root'

[HIGH] SSH password spraying
    IP: 192.0.2.44  attempts: 5  MITRE: T1110.003
    users: admin, oracle, pi, test, ubuntu
```

Analyze your own server (read-only):

```bash
sudo logsentinel ssh /var/log/auth.log          # Debian/Ubuntu
sudo logsentinel ssh /var/log/secure --json     # RHEL/Fedora, JSON output
```

Options: `--threshold N` (default 5), `--window SECONDS` (default 300), `--json`.
The exit code is `1` when threats are found, so it can be used in scripts and cron jobs.

## How detection works

1. **Parse** — regexes normalize `sshd` lines into `AuthEvent` objects (time, IP, user, success).
2. **Sliding window** — for each source IP, failed attempts are kept in a time window.
   When the count crosses the threshold, an alert is raised.
3. **Classify** — ≥3 distinct usernames ⇒ *password spraying*; otherwise *brute force*.
4. **Correlate** — a successful login from an IP with an active alert escalates it to **CRITICAL**.

```
auth.log ─► parser ─► AuthEvent stream ─► detector (sliding window per IP) ─► Alerts ─► table / JSON
```

## Project structure

```
src/logsentinel/
├── cli.py                 # command-line interface
├── models.py              # AuthEvent, Alert, Severity
├── parsers/ssh.py         # OpenSSH log parser
└── detectors/bruteforce.py
tests/                     # pytest suite (run in GitHub Actions)
samples/                   # synthetic logs (RFC 5737 documentation IPs)
```

## Development

```bash
pip install -e ".[dev]"
pytest -v && ruff check .
```

## Roadmap

- [x] SSH brute force / spraying / compromise detection
- [ ] Apache/Nginx parser with SQLi, XSS and scanner detection
- [ ] Rules in YAML (Sigma-inspired)
- [ ] HTML report
- [ ] IP reputation enrichment (AbuseIPDB)

## License

MIT
