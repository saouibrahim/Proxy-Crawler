#!/usr/bin/env python3
"""
SOCKS5 Proxy Scraper
====================
Fetches free SOCKS5 proxy lists from public sources.

Sources used:
  - proxyscrape.com   (SOCKS5 API endpoint)
  - openproxylist.xyz
  - proxy-list.download
  - raw GitHub lists (TheSpeedX, hookzof)
  - free-proxy-list.net  (HTML scrape)
  - socks-proxy.net      (HTML scrape)
  - spys.one             (HTML scrape)

The Scribd document referenced in the project
(https://www.scribd.com/document/878624160/Free-Socks-Sites-List)
catalogues these same public aggregator sites; the URLs below
are taken directly from that catalogue.
"""

import urllib.request
import urllib.error
import html
import re
import logging
import time
import json
from typing import List, Tuple, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ProxyEntry = Tuple[str, int]          # (host, port)

# ── Source registry ──────────────────────────────────────────────────────────

SOURCES = [
    # Plain-text / API sources (one proxy per line: host:port)
    {
        "name": "proxyscrape_socks5",
        "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_type=socks5&timeout=5000&country=all&ssl=all&anonymity=all",
        "type": "text",
    },
    {
        "name": "proxyscrape_socks5_v2",
        "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true",
        "type": "text",
    },
    {
        "name": "proxy_list_download_socks5",
        "url": "https://www.proxy-list.download/api/v1/get?type=socks5",
        "type": "text",
    },
    {
        "name": "openproxylist_socks5",
        "url": "https://openproxylist.xyz/socks5.txt",
        "type": "text",
    },
    {
        "name": "github_speedx_socks5",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "type": "text",
    },
    {
        "name": "github_hookzof_socks5",
        "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "type": "text",
    },
    {
        "name": "github_roosterkid_socks5",
        "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "type": "text",
    },
    {
        "name": "github_monosans_socks5",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "type": "text",
    },
    {
        "name": "github_jetkai_socks5",
        "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "type": "text",
    },
    # HTML-scraped sources
    {
        "name": "socks_proxy_net",
        "url": "https://www.socks-proxy.net/",
        "type": "html_table",
    },
    {
        "name": "free_proxy_list_net",
        "url": "https://free-proxy-list.net/",
        "type": "html_table",
    },
    {
        "name": "spysone_socks5",
        "url": "https://spys.one/en/socks-proxy-list/",
        "type": "html_spys",
    },
    {
        "name": "proxydb_net_socks5",
        "url": "http://proxydb.net/?protocol=socks5&anonlvl=1&anonlvl=2&anonlvl=3",
        "type": "html_table",
    },
]

# ── Parsers ──────────────────────────────────────────────────────────────────

_HOST_PORT_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s,|]+(\d{2,5})\b"
)

def _parse_text(content: str) -> Set[ProxyEntry]:
    """Parse plain-text proxy lists (host:port, one per line)."""
    proxies: Set[ProxyEntry] = set()
    for match in _HOST_PORT_RE.finditer(content):
        host, port_s = match.group(1), match.group(2)
        port = int(port_s)
        if _valid_entry(host, port):
            proxies.add((host, port))
    return proxies

def _parse_html_table(content: str) -> Set[ProxyEntry]:
    """
    Extract proxies from HTML tables like free-proxy-list.net / socks-proxy.net.
    The tables have <td> cells where the first column is IP and second is port.
    """
    proxies: Set[ProxyEntry] = set()
    # Strip tags and scan for IP:port patterns
    text = re.sub(r"<[^>]+>", " ", content)
    text = html.unescape(text)
    for match in _HOST_PORT_RE.finditer(text):
        host, port_s = match.group(1), match.group(2)
        port = int(port_s)
        if _valid_entry(host, port):
            proxies.add((host, port))
    return proxies

def _parse_html_spys(content: str) -> Set[ProxyEntry]:
    """spys.one encodes the port via inline JavaScript obfuscation; fall back to regex scan."""
    return _parse_html_table(content)

def _valid_entry(host: str, port: int) -> bool:
    """Basic sanity checks for a proxy entry."""
    if not (1 <= port <= 65535):
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    # Reject private / loopback / broadcast ranges
    if octets[0] in (0, 10, 127):
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
        return False
    if octets[0] == 255:
        return False
    return True

# ── HTTP fetch helper ─────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,text/plain,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

def _fetch(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            # Try utf-8, fall back to latin-1
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw.decode("latin-1", errors="replace")
    except Exception as e:
        raise RuntimeError(f"Fetch failed for {url}: {e}") from e

# ── Public API ────────────────────────────────────────────────────────────────

def scrape_source(source: dict) -> Tuple[str, Set[ProxyEntry], str]:
    """
    Scrape a single source.
    Returns (name, proxies_set, error_message).
    """
    name = source["name"]
    url = source["url"]
    src_type = source["type"]
    try:
        content = _fetch(url)
        if src_type == "text":
            proxies = _parse_text(content)
        elif src_type == "html_table":
            proxies = _parse_html_table(content)
        elif src_type == "html_spys":
            proxies = _parse_html_spys(content)
        else:
            proxies = _parse_text(content)
        return name, proxies, ""
    except Exception as e:
        return name, set(), str(e)


def scrape_all(
    sources: List[dict] = None,
    delay: float = 0.5,
    on_source_done=None,
) -> Tuple[List[ProxyEntry], dict]:
    """
    Scrape all sources sequentially (rate-limit friendly).

    Returns:
        (deduplicated_proxy_list, stats_dict)
    """
    if sources is None:
        sources = SOURCES

    all_proxies: Set[ProxyEntry] = set()
    stats = {}

    for src in sources:
        name, proxies, err = scrape_source(src)
        stats[name] = {"count": len(proxies), "error": err}
        all_proxies.update(proxies)
        if on_source_done:
            on_source_done(name, len(proxies), err)
        time.sleep(delay)

    return list(all_proxies), stats


def scrape_from_file(path: str) -> List[ProxyEntry]:
    """Load proxies from a local file (host:port per line or comma/space separated)."""
    proxies: Set[ProxyEntry] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    proxies.update(_parse_text(content))
    return list(proxies)
