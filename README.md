# 🛡️ LogSentinel

![CI](https://github.com/FMBeca/logsentinel/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**LogSentinel** is a lightweight CLI with no required dependencies that detects attacks in Linux and web server log files
and maps every alert to **MITRE ATT&CK**. It's built to show how SOC detection logic works
under the hood — the same ideas SIEMs like Splunk, Elastic or Wazuh apply at scale.

## Features

| Detection | Rule | MITRE ATT&CK | Status |
|---|---|---|---|
| SSH brute force (one user, many attempts) | LS-SSH-001 | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | ✅ |
| SSH password spraying (many users) | LS-SSH-001 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | ✅ |
| Successful login after brute force (likely compromise) | LS-SSH-001 | T1110 + [T1078](https://attack.mitre.org/techniques/T1078/) | ✅ |
| SQL injection attempts | LS-WEB-001 | [T1190](https://attack.mitre.org/techniques/T1190/) | ✅ |
| Cross-site scripting (XSS) attempts | LS-WEB-002 | [T1190](https://attack.mitre.org/techniques/T1190/) | ✅ |
| Path traversal / local file inclusion | LS-WEB-003 | [T1190](https://attack.mitre.org/techniques/T1190/) | ✅ |
| Directory / file brute force (behavioural) | LS-WEB-004 | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | ✅ |
| Known scanner User-Agents (Nikto, sqlmap, gobuster, ffuf…) | LS-WEB-005 | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | ✅ |
| Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)), incl. obfuscated payloads in headers | LS-WEB-006 | [T1190](https://attack.mitre.org/techniques/T1190/) | ✅ |
| Custom rules in Sigma format (web subset) | rule `id` | from the rule's `attack.tXXXX` tags | ✅ |
| Self-contained HTML report (`--html`) | — | — | ✅ |

## Quick start

```bash
git clone https://github.com/FMBeca/logsentinel.git
cd logsentinel
pip install -e .
logsentinel ssh samples/auth.log --year 2026
logsentinel web samples/access.log
```

Example output:

```
[CRITICAL] Successful login after SSH brute force  (LS-SSH-001)
    IP: 203.0.113.5  events: 6  MITRE: T1110.001, T1078
    2026-11-22 14:01:02 -> 2026-11-22 14:01:12
    users: root
    !! login succeeded as 'root'

[HIGH] SSH password spraying  (LS-SSH-001)
    IP: 192.0.2.44  events: 5  MITRE: T1110.003
    users: admin, oracle, pi, test, ubuntu
```

Web log analysis of [`samples/access.log`](samples/access.log) — SQLi, Log4Shell, path traversal,
XSS, and two wordlist scans, one of them hiding behind a browser User-Agent:

<p align="center">
  <img src="docs/demo-web.png" width="600"
       alt="logsentinel web output: HIGH alerts for SQL injection, path traversal and Log4Shell, MEDIUM alerts for directory brute force and XSS, LOW alerts for gobuster, sqlmap and Nikto User-Agents">
</p>

Analyze your own server (read-only):

```bash
sudo logsentinel ssh /var/log/auth.log          # Debian/Ubuntu
sudo logsentinel ssh /var/log/secure --json     # RHEL/Fedora, JSON output
sudo logsentinel web /var/log/nginx/access.log
sudo logsentinel web /var/log/apache2/access.log --json
```

| Command | Options |
|---|---|
| `ssh` | `--threshold N` (default 5), `--window SECONDS` (default 300), `--year YYYY` |
| `web` | `--scan-threshold N` distinct 403/404 paths (default 20), `--scan-window SECONDS` (default 60), `--rules PATH` (repeatable) |

Both accept `--json`, `--no-color`, `--html FILE` and `-` to read from stdin.
The exit code is `1` when threats are found, so it can be used in scripts and cron jobs,
and `2` when a rule file cannot be loaded.

## HTML report

```bash
logsentinel web samples/access.log --rules rules/web --html report.html
```

`--html` writes a single file that opens in any browser, works offline and can be attached to a
ticket: a summary by severity, the MITRE ATT&CK techniques seen (linked to attack.mitre.org) and every
alert with its evidence. The console output and exit code stay the same.

Log lines are attacker-controlled, so a report that pasted them into HTML would run an attacker's XSS
payload in the analyst's browser. Every value is HTML-escaped, and the page carries a
Content-Security-Policy that blocks scripts and remote resources as a second layer; the tests feed
XSS payloads through every field of an alert to check both.

## Custom rules (Sigma format)

[Sigma](https://github.com/SigmaHQ/sigma) is the open format SOC teams use to share detection
rules. The `web` command can load extra rules written in a subset of it, on top of the built-in ones:

```bash
pip install -e ".[yaml]"                      # PyYAML is only needed for rule files
logsentinel web samples/access.log --rules rules/web
```

```yaml
title: Web shell access attempt
id: 81e90d38-7eac-48ec-9c90-939a75ecabb4
tags: [attack.persistence, attack.t1505.003]
logsource:
  category: webserver
detection:
  selection_name:
    cs-uri-stem|endswith: [/shell.php, /cmd.php, /c99.php]
  selection_param:
    cs-uri-stem|endswith: .php
    cs-uri-query|contains: [cmd=, exec=]
  condition: 1 of selection_*
level: high
```

Two example rules live in [`rules/web/`](rules/web): web shell access (T1505.003) and probes for
backups, database dumps and `.env` / `.git` files (T1552.001).

| Supported | |
|---|---|
| Log source | `category: webserver` (`product: apache` / `nginx` or none) |
| Fields | `c-ip`, `cs-method`, `cs-uri`, `cs-uri-stem`, `cs-uri-query`, `cs-version`, `sc-status`, `sc-bytes`, `c-useragent`, `cs-referer` |
| Values | case-insensitive, `*` / `?` wildcards, lists (OR), `null`, keyword lists (raw line) |
| Modifiers | `contains`, `startswith`, `endswith`, `all`, `re` (`re\|i` for case-insensitive) |
| Conditions | `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them` |

URL and header fields are matched both as logged and after normalization, so a rule written for
`' or 1=1` also catches `%27%20or%201%3D1`. Anything outside this subset (aggregations, `timeframe`,
other log sources, unknown modifiers or fields) is **rejected with an error** instead of being skipped:
a rule that loads but can never fire gives a false sense of coverage.

## How detection works

### SSH

1. **Parse** — regexes normalize `sshd` lines into `AuthEvent` objects (time, IP, user, success).
2. **Sliding window** — for each source IP, failed attempts are kept in a time window.
   When the count crosses the threshold, an alert is raised.
3. **Classify** — ≥3 distinct usernames ⇒ *password spraying*; otherwise *brute force*.
4. **Correlate** — a successful login from an IP with an active alert escalates it to **CRITICAL**
   and adds T1078 (Valid Accounts): the attacker now holds working credentials.

```
auth.log ─► parser ─► AuthEvent stream ─► detector (sliding window per IP) ─► Alerts ─► table / JSON
```

### Web (Apache / Nginx)

1. **Parse** — the Combined Log Format (and the shorter Common Log Format) is normalized into
   `HttpEvent` objects. Malformed requests, such as TLS handshakes sent to a plain-HTTP port,
   are kept because they are often interesting.
2. **Normalize** — the request target is URL-decoded **twice** (to defeat double encoding such as
   `%2527` → `%27` → `'`) and SQL inline comments (`/**/`), a common way to replace spaces, are stripped.
3. **Signatures** — regex rules for SQLi, XSS and path traversal run against every request.
   They are tested against benign look-alikes (`?q=select+your+plan`, `/docs/../img/logo.png`)
   to keep false positives down. The Log4Shell rule also inspects the User-Agent and Referer,
   where that payload was usually sent, after unwrapping Log4j lookups used to hide it
   (`${${lower:j}ndi:...}` → `${jndi:...}`).
4. **Behaviour** — per source IP, a sliding window counts *distinct* paths answered with 403/404.
   A User-Agent can be changed with one flag (`gobuster -a`), so this is what catches wordlist
   scanners that pretend to be a browser; the User-Agent rule is only a low-confidence extra signal.

> Signature hits are **attempts**, not proof of compromise: a `200` response to a SQLi payload
> may simply mean the application ignored it. Status codes are included in every alert to help triage.

## Project structure

```
src/logsentinel/
├── cli.py                 # command-line interface
├── models.py              # AuthEvent, HttpEvent, Alert, Severity
├── sigma.py               # Sigma-style YAML rule loader and matcher
├── report.py              # self-contained HTML report
├── parsers/
│   ├── ssh.py             # OpenSSH log parser
│   └── web.py             # Apache/Nginx access log parser
└── detectors/
    ├── bruteforce.py      # SSH brute force / spraying
    └── web.py             # SQLi, XSS, traversal, scanners
rules/web/                 # example rules in Sigma format
tests/                     # pytest suite (run in GitHub Actions)
samples/                   # synthetic logs (RFC 5737 documentation IPs)
scripts/gen_access_log.py  # regenerates samples/access.log (kept in sync by a test)
```

## Development

```bash
pip install -e ".[dev]"
pytest -v && ruff check .
```

## Roadmap

- [x] SSH brute force / spraying / compromise detection
- [x] Apache/Nginx parser with SQLi, XSS, path traversal and scanner detection
- [x] Custom rules in Sigma format (web subset)
- [x] HTML report
- [ ] IP reputation enrichment (AbuseIPDB)

## License

MIT
