# SOCKS5 Proxy Toolkit

A complete, dependency-free Python3 toolkit for **scraping**, **validating**, and **managing** free SOCKS5 proxies.  
Built on a solid understanding of the SOCKS protocol — RFC 1928 (SOCKS v5) and RFC 1929 (username/password auth).

```
socks5-toolkit/
├── main.py                  ← CLI entry point
├── src/
│   ├── socks5_checker.py    ← RFC 1928 handshake implementation
│   ├── scraper.py           ← Multi-source proxy scraper
│   └── formatters.py        ← JSON / CSV / TXT output
├── tests/
│   └── test_toolkit.py      ← 15 unit tests (mock server included)
├── config/                  ← Drop custom source lists here
├── output/                  ← Default output directory
└── README.md
```

---

## Background — What is SOCKS5?

SOCKS (Socket Secure) is a generic **Transport-layer proxy protocol** that sits between the Application and Transport layers of the OSI model.  
Unlike HTTP proxies that only handle web traffic, SOCKS proxies can relay **any TCP or UDP connection**.

### SOCKS v4 vs v5

| Feature     | SOCKS v4 | SOCKS v5 |
|   ---       |    ---   |    ---   |
| TCP support | ✓ | ✓ |
| UDP support | ✗ | ✓ |
| Authentication | Ident (RFC 931) only | Username/Password, GSSAPI |
| IPv6 | ✗ | ✓ |
| Remote DNS | Partial | ✓ |
| Default port | 1080 | 1080 |

This toolkit targets **SOCKS v5 exclusively** (Cisco SWA/WSA also drops v4 support in modern deployments).

### How the SOCKS5 Handshake Works (RFC 1928)

```
Client                                     SOCKS Proxy
  │                                              │
  │── Client Negotiation ─────────────────────►  │
  │   VER=5 | NMETHODS | METHODS[]               │
  │                                              │
  │◄─ Server Negotiation ─────────────────────   │
  │   VER=5 | METHOD (chosen)                    │
  │                                              │
  │── Authentication (RFC 1929, if required) ──► │
  │   VER=1 | ULEN | UNAME | PLEN | PASSWD       │
  │                                              │
  │◄─ Auth Reply ────────────────────────────    │
  │   VER=1 | STATUS (0=ok)                      │
  │                                              │
  │── Client Request ───────────────────────── ► │
  │   VER=5 | CMD=CONNECT | RSV | ATYP           │
  │   DST.ADDR | DST.PORT                        │
  │                                              │
  │◄─ Server Reply ──────────────────────────    │
  │   VER=5 | REP=0x00 (success) | RSV | ATYP    │
  │   BND.ADDR | BND.PORT                        │
  │                                              │
  │◄════════════ Data flows freely ══════════►   │
```

The proxy then:
1. Evaluates the request against its **ACL** (access control list)  
2. Establishes the outbound TCP connection to `DST.ADDR:DST.PORT`  
3. Transparently forwards all data in both directions

This toolkit reproduces steps 1–5 to determine whether a proxy is alive and responsive.

---

## Requirements

- **Python 3.8+**  
- **Zero external dependencies** — uses only Python3's standard library (`socket`, `struct`, `threading`, `concurrent.futures`, `urllib.request`, `csv`, `json`, `argparse`)

---

## Installation

```bash
git clone https://github.com/you/socks5-toolkit
cd socks5-toolkit
# No pip install needed — stdlib only
python3 main.py --help
```

---

## Usage

### 1. Probe a single proxy

Immediately test one proxy with a full SOCKS5 handshake:

```bash
python3 main.py probe 1.2.3.4:1080
```

With username/password authentication (RFC 1929):

```bash
python3 main.py probe 1.2.3.4:1080 -u alice -p secret
```

Custom test target and timeout:

```bash
python3 main.py probe 1.2.3.4:1080 --test-host google.com --test-port 443 --timeout 8
```

Exit code is `0` if alive, `1` if dead — suitable for scripting.

---

### 2. Bulk-check a proxy file

Check all proxies in a file concurrently:

```bash
python3 main.py check --input proxies.txt --out output/results.json --format json
```

The input file can contain proxies in any common format:

```
1.2.3.4:1080
5.6.7.8 1080
9.10.11.12,1080
```

Options:

```
-i / --input       Path to proxy list file (required)
-o / --out         Output file path
-f / --format      json | csv | txt | auto  (auto = infer from extension)
-w / --workers     Concurrent threads (default: 50)
     --timeout     Per-proxy timeout in seconds (default: 5.0)
     --test-host   Host to CONNECT through proxy (default: httpbin.org)
     --test-port   Port for test connection (default: 80)
     --all         Include dead proxies in output (default: alive only)
-q / --quiet       Suppress progress table
```

---

### 3. Scrape free proxy sources

Pull proxies from 12+ public sources:

```bash
python3 socks5-toolkit/main.py scrape --out output/raw.txt
```

This fetches from:

| Source | Type |
|---|---|
| proxyscrape.com API (v2 + v3) | Plain-text |
| proxy-list.download | Plain-text |
| openproxylist.xyz | Plain-text |
| github.com/TheSpeedX/PROXY-List | Plain-text |
| github.com/hookzof/socks5_list | Plain-text |
| github.com/roosterkid/openproxylist | Plain-text |
| github.com/monosans/proxy-list | Plain-text |
| github.com/jetkai/proxy-list | Plain-text |
| socks-proxy.net | HTML scrape |
| free-proxy-list.net | HTML scrape |
| spys.one | HTML scrape |
| proxydb.net | HTML scrape |

All scraped proxies are **deduplicated** and **filtered** (private IP ranges, loopback, broadcast are removed automatically).

---

### 4. Scrape then check (the main workflow)

The most useful command — scrape all sources, then validate every proxy:

```bash
python3 socks5-toolkit/main.py scrape-check --workers 150 --out output/alive.json --format json
```

Full workflow:
```
Step 1/2  –  Scraping 12 sources …
  proxyscrape_socks5               ✓  843 proxies
  github_speedx_socks5             ✓ 3241 proxies
  socks_proxy_net                  ✓   80 proxies
  …

  → 4512 unique proxies scraped

Step 2/2  –  Checking 4512 proxies (150 workers, timeout=5s) …

[4512/4512] 100.0%  alive=312  189.3/s  ✓ 45.67.89.12:1080 44ms

┌─────────────────────────────────────┐
│          CHECK SUMMARY              │
├─────────────────────────────────────┤
│  Total checked : 4512               │
│  Alive         : 312                │
│  Dead          : 4200               │
│  Success rate  :     6.9 %          │
├─────────────────────────────────────┤
│  Avg latency   :  1823.4 ms         │
│  Min latency   :    44.2 ms         │
│  Max latency   :  4987.1 ms         │
└─────────────────────────────────────┘
```

Additional options:

```
--limit N          Random sample of N proxies (useful for quick tests)
--delay SECS       Delay between scrape requests (default: 0.5, be polite)
```

---

## Output Formats

### Plain-text (default for `.txt`)
```
1.2.3.4:1080
5.6.7.8:4145
```
Ready to paste into browser proxy settings or tools like `proxychains`.

### JSON (`.json`)
```json
[
  {
    "host": "1.2.3.4",
    "port": 1080,
    "alive": true,
    "latency_ms": 342.1,
    "country": "",
    "username": "",
    "password": "",
    "reply_code": 0,
    "error": "",
    "checked_at": "2026-03-24T09:00:00Z"
  }
]
```

### CSV (`.csv`)
```
host,port,alive,latency_ms,country,username,password,reply_code,error,checked_at
1.2.3.4,1080,True,342.1,,,,0,,2026-03-24T09:00:00Z
```

When you save to a non-`.txt` format, a companion `_alive.txt` plain-text file is also written for convenience.

---

## Using the toolkit as a library

```python3
from src.socks5_checker import check_proxy, check_proxies_bulk, SOCKS5Handshake
from src.scraper import scrape_all
from src.formatters import to_json, save

# Single probe
result = check_proxy("1.2.3.4", 1080, timeout=5.0, test_host="google.com")
print(result.alive, result.latency_ms)

# Authenticated proxy
result = check_proxy("1.2.3.4", 1080, username="user", password="pass")

# Raw RFC 1928 handshake
hs = SOCKS5Handshake("1.2.3.4", 1080)
alive, latency_ms, reply_code, error = hs.check("httpbin.org", 80)

# Bulk check
proxies = [("1.2.3.4", 1080), ("5.6.7.8", 1080)]
results = check_proxies_bulk(proxies, workers=50, timeout=5.0)

# Scrape all sources
proxy_list, stats = scrape_all()
# proxy_list = [("1.2.3.4", 1080), ...]

# Save results
save(results, "output/alive.json", fmt="json", alive_only=True)
```

---

## Running Tests

All 15 tests use only stdlib — no external test runner needed:

```bash
python3 tests/test_toolkit.py -v
```

Expected output:
```
test_summary (TestFormatters) ... ok
test_to_csv (TestFormatters) ... ok
test_to_json (TestFormatters) ... ok
test_to_plain_text_alive_only (TestFormatters) ... ok
test_parse_html_table (TestParser) ... ok
test_parse_text_basic (TestParser) ... ok
test_parse_text_filters_private (TestParser) ... ok
test_parse_weird_separators (TestParser) ... ok
test_valid_entry (TestParser) ... ok
test_auth_success (TestSOCKS5Handshake) ... ok
test_auth_wrong_password (TestSOCKS5Handshake) ... ok
test_conn_refused (TestSOCKS5Handshake) ... ok
test_no_auth_success (TestSOCKS5Handshake) ... ok
test_proxy_returns_error_reply (TestSOCKS5Handshake) ... ok
test_timeout (TestSOCKS5Handshake) ... ok

Ran 15 tests in 0.011s  OK
```

The `TestSOCKS5Handshake` suite spins up a real **in-process mock SOCKS5 server** and exercises the full RFC 1928 packet exchange — no live internet required.

---

## Performance Tuning

| Scenario | Recommended `--workers` | `--timeout` |
|---|---|---|
| Quick spot-check (< 500 proxies) | 50 | 5s |
| Full scrape-check (thousands) | 100–200 | 4s |
| Low-latency targets only | 200+ | 2s |

More workers help with I/O-bound proxy checking (most time is spent waiting for TCP handshake responses). The GIL is not a bottleneck here.

---

## Protocol Reference

| RFC | Title |
|---|---|
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 |
| [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) | Username/Password Auth for SOCKS V5 |
| [RFC 1961](https://www.rfc-editor.org/rfc/rfc1961) | GSS-API Auth for SOCKS V5 |

The documents bundled with this project provide additional context:

| File | Description |
|---|---|
| `Socks_v5_Proxy_Protocol.pdf` | Linux Magazine article — complete SOCKSv5 explanation, packet diagrams, Dante configuration |
| `222544configureandexaminesocksproxyonsec.pdf` | Cisco SWA/WSA SOCKS proxy configuration and troubleshooting guide |
| `slides99intareasocks600.pdf` | IETF slides on SOCKSv6 — improvements over v5 (reduced RTTs, TFO, 0-RTT auth) |
| `104018.pdf` | SANS GIAC paper — comprehensive SOCKSv4/v5 implementation guide with Dante, NEC, Hummingbird, Aventail |

---

## SOCKS5 Packet Reference

From RFC 1928 (as documented in the bundled Linux Magazine article):

| Field | Size | Description |
|---|---|---|
| `VER` | 1 byte | Protocol version = `0x05` |
| `CMD` | 1 byte | `0x01` CONNECT, `0x02` BIND, `0x03` UDP ASSOCIATE |
| `ATYP` | 1 byte | `0x01` IPv4, `0x03` Domain name, `0x04` IPv6 |
| `DST.ADDR` | Variable | Target address (4B IPv4, 16B IPv6, or 1B length + N bytes domain) |
| `DST.PORT` | 2 bytes | Target port (big-endian) |
| `REP` | 1 byte | Reply: `0x00` success, `0x01`–`0x08` various errors |
| `BND.ADDR` | Variable | Proxy's bound address for the connection |
| `BND.PORT` | 2 bytes | Proxy's bound port for the connection |

---

## Free Proxy Source Catalogue

As documented in the Scribd reference list, these are the most reliable public SOCKS5 sources (all included in the scraper):

- **proxyscrape.com** — dedicated API, updated frequently  
- **TheSpeedX/PROXY-List** (GitHub) — large, community-maintained  
- **hookzof/socks5_list** (GitHub) — SOCKS5-only list  
- **monosans/proxy-list** (GitHub) — verified proxies  
- **roosterkid/openproxylist** (GitHub)  
- **jetkai/proxy-list** (GitHub)  
- **socks-proxy.net** — classic HTML table  
- **spys.one** — aggregator with JS-obfuscated ports (scraped via regex fallback)  
- **proxy-list.download** — API endpoint  
- **openproxylist.xyz** — plain-text API  
- **proxydb.net** — filterable database  
- **free-proxy-list.net** — HTML table scrape  

> ⚠️ **Note:** Free proxy lists have a high churn rate. Even fresh lists typically have a liveness rate of 5–15%. Always check before use.

---

## Legal & Ethical Use

- Use only for **legitimate purposes**: privacy, research, development, testing  
- Respect the **terms of service** of the websites you route through proxies  
- Do not use for scraping, spamming, or circumventing access controls you don't have permission to bypass  
- Free proxies are operated by third parties — **never send sensitive data** (passwords, tokens, PII) through them  
