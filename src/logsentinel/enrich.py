"""Optional IP reputation enrichment with AbuseIPDB (https://www.abuseipdb.com).

Off by default: it sends the source IPs of your alerts to a third party and needs an API key.
Design choices:

* The key is read from the ABUSEIPDB_API_KEY environment variable, never from a command-line
  argument (arguments end up in shell history and in the process list), and it travels in an
  HTTP header, never in the URL (URLs end up in proxy logs).
* Only globally routable addresses are looked up: private, loopback and documentation ranges
  never leave the machine.
* Enrichment never breaks detection: network errors, a rejected key or an exhausted quota
  produce a warning and the alerts are reported without reputation data.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from urllib.parse import urlencode

from logsentinel.models import Alert

API_URL = "https://api.abuseipdb.com/api/v2/check"
ENV_KEY = "ABUSEIPDB_API_KEY"
TIMEOUT = 10.0

Fetch = Callable[[str, dict[str, str]], dict]


class EnrichError(ValueError):
    """Enrichment cannot start (for example, no API key)."""


def _http_fetch(url: str, headers: dict[str, str]) -> dict:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:   # fixed https URL, no user input
        return json.load(resp)


def is_public(ip: str) -> bool:
    """True only for globally routable addresses (not private, loopback or documentation)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class AbuseIPDB:
    def __init__(self, api_key: str, fetch: Fetch | None = None, max_age_days: int = 90) -> None:
        if not api_key:
            raise EnrichError(f"--enrich needs an AbuseIPDB API key in the {ENV_KEY} environment variable")
        self._key = api_key
        self._fetch = fetch or _http_fetch
        self._max_age = max_age_days
        self._cache: dict[str, dict | None] = {}
        self._stopped = False
        self.warnings: list[str] = []
        self.lookups = 0

    def _stop(self, reason: str) -> None:
        self._stopped = True
        self.warnings.append(f"AbuseIPDB enrichment stopped: {reason}")

    def lookup(self, ip: str) -> dict | None:
        if not is_public(ip):
            return None
        if ip in self._cache:
            return self._cache[ip]
        if self._stopped:
            return None

        url = f"{API_URL}?{urlencode({'ipAddress': ip, 'maxAgeInDays': self._max_age})}"
        headers = {"Key": self._key, "Accept": "application/json"}
        rep = None
        try:
            self.lookups += 1
            data = self._fetch(url, headers)["data"]
            rep = {
                "source": "AbuseIPDB",
                "score": int(data.get("abuseConfidenceScore") or 0),
                "reports": int(data.get("totalReports") or 0),
                "country": str(data.get("countryCode") or ""),
                "isp": str(data.get("isp") or ""),
                "usage": str(data.get("usageType") or ""),
                "tor": bool(data.get("isTor")),
                "last_reported": str(data.get("lastReportedAt") or ""),
            }
        except urllib.error.HTTPError as exc:          # before URLError: it is a subclass
            if exc.code in (401, 403):
                self._stop(f"API key rejected (HTTP {exc.code})")
            elif exc.code == 429:
                self._stop("daily quota or rate limit reached (HTTP 429)")
            else:
                self.warnings.append(f"AbuseIPDB lookup for {ip} failed (HTTP {exc.code})")
        except (urllib.error.URLError, OSError) as exc:
            # Network down or DNS failure: stop, instead of waiting for a timeout per IP.
            self._stop(f"cannot reach the API ({exc.__class__.__name__})")
        except (KeyError, TypeError, ValueError, AttributeError):
            self.warnings.append(f"AbuseIPDB returned an unexpected response for {ip}")
        self._cache[ip] = rep
        return rep


def enrich(alerts: Iterable[Alert], client: AbuseIPDB) -> int:
    """Add details["reputation"] to every alert whose source IP could be looked up."""
    enriched = 0
    for a in alerts:
        rep = client.lookup(a.source_ip)
        if rep is not None:
            a.details["reputation"] = rep
            enriched += 1
    return enriched
