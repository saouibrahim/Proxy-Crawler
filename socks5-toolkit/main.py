#!/usr/bin/env python3
"""
socks5-toolkit  –  CLI entry point
====================================

Usage examples:

  # Scrape free proxies and check them, save alive ones
  python main.py scrape-check --workers 100 --out output/alive.txt

  # Check a specific list
  python main.py check --input proxies.txt --out output/results.json --format json

  # Quick check a single proxy
  python main.py probe 123.45.67.89:1080

  # Only scrape (no check), save raw list
  python main.py scrape --out output/raw.txt

Run `python main.py --help` for full options.
"""

import argparse
import logging
import os
import sys
import time

# ── Make sure src/ is on the path ─────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from scraper       import scrape_all, scrape_from_file, SOURCES
from socks5_checker import check_proxy, check_proxies_bulk
from formatters     import to_table, summary, save, to_plain_text


# ── Logging ────────────────────────────────────────────────────────────────────

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ── Progress helper ────────────────────────────────────────────────────────────

class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done  = 0
        self.alive = 0
        self._lock = __import__("threading").Lock()
        self._start = time.monotonic()

    def tick(self, result):
        with self._lock:
            self.done += 1
            if result.alive:
                self.alive += 1
            elapsed = time.monotonic() - self._start
            rate = self.done / elapsed if elapsed > 0 else 0
            pct = self.done / self.total * 100 if self.total else 0
            sym = "✓" if result.alive else "✗"
            lat = f"{result.latency_ms:.0f}ms" if result.latency_ms >= 0 else "—"
            print(
                f"\r[{self.done}/{self.total}] {pct:5.1f}%  "
                f"alive={self.alive}  {rate:.1f}/s  "
                f"{sym} {result.host}:{result.port} {lat}          ",
                end="", flush=True
            )


# ── Sub-commands ───────────────────────────────────────────────────────────────

def cmd_probe(args):
    """Check a single proxy immediately."""
    addr = args.proxy.strip()
    if ":" not in addr:
        print(f"[ERROR] Expected host:port, got: {addr}", file=sys.stderr)
        sys.exit(1)

    host, port_s = addr.rsplit(":", 1)
    port = int(port_s)
    user = args.username or None
    pwd  = args.password or None

    print(f"Probing {host}:{port} …")
    r = check_proxy(
        host, port,
        username=user, password=pwd,
        timeout=args.timeout,
        test_host=args.test_host,
        test_port=args.test_port,
    )
    if r.alive:
        print(f"  ✓  ALIVE  —  latency {r.latency_ms:.1f} ms")
    else:
        print(f"  ✗  DEAD   —  {r.error}")
    sys.exit(0 if r.alive else 1)


def cmd_check(args):
    """Bulk-check proxies from a file."""
    if not os.path.exists(args.input):
        print(f"[ERROR] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    proxies = scrape_from_file(args.input)
    if not proxies:
        print("[WARN] No valid proxy entries found in file.")
        sys.exit(0)

    print(f"Loaded {len(proxies)} proxies from {args.input}")
    print(f"Checking with {args.workers} workers, timeout={args.timeout}s …\n")

    prog = Progress(len(proxies))
    results = check_proxies_bulk(
        proxies,
        workers=args.workers,
        timeout=args.timeout,
        test_host=args.test_host,
        test_port=args.test_port,
        on_result=prog.tick,
    )
    print()  # newline after progress

    _print_and_save(results, args)


def cmd_scrape(args):
    """Scrape free proxy sources and save raw list."""
    print(f"Scraping {len(SOURCES)} proxy sources …")

    def on_done(name, count, err):
        status = f"✓ {count:>4} proxies" if not err else f"✗ ERROR: {err[:60]}"
        print(f"  {name:<40} {status}")

    proxies, stats = scrape_all(on_source_done=on_done, delay=args.delay)
    print(f"\nTotal unique proxies scraped: {len(proxies)}")

    if args.out:
        lines = [f"{h}:{p}" for h, p in proxies]
        content = "\n".join(lines)
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            f.write(content)
        print(f"Saved to {args.out}")


def cmd_scrape_check(args):
    """Scrape then immediately check all scraped proxies."""
    print(f"Step 1/2  –  Scraping {len(SOURCES)} sources …\n")

    def on_done(name, count, err):
        status = f"✓ {count:>4}" if not err else f"✗ ERR"
        print(f"  {name:<40} {status}")

    proxies, _ = scrape_all(on_source_done=on_done, delay=args.delay)
    print(f"\n  → {len(proxies)} unique proxies scraped\n")

    if not proxies:
        print("[WARN] Nothing to check.")
        sys.exit(0)

    # Optional limit
    if args.limit and len(proxies) > args.limit:
        import random
        proxies = random.sample(proxies, args.limit)
        print(f"  → Randomly sampled {args.limit} proxies for checking\n")

    print(f"Step 2/2  –  Checking {len(proxies)} proxies "
          f"({args.workers} workers, timeout={args.timeout}s) …\n")

    prog = Progress(len(proxies))
    results = check_proxies_bulk(
        proxies,
        workers=args.workers,
        timeout=args.timeout,
        test_host=args.test_host,
        test_port=args.test_port,
        on_result=prog.tick,
    )
    print()

    _print_and_save(results, args)


# ── Shared print+save logic ────────────────────────────────────────────────────

def _print_and_save(results, args):
    print()
    print(summary(results))
    print()

    alive_results = [r for r in results if r.alive]

    if not args.quiet:
        print(to_table(results, alive_only=True, max_rows=50))
        print()

    if args.out:
        fmt = args.format or "auto"
        save(results, args.out, fmt=fmt, alive_only=not args.all)
        print(f"Saved {len(alive_results)} alive proxies → {args.out}")

        # Always also write a plain alive.txt alongside for convenience
        base, ext = os.path.splitext(args.out)
        if ext != ".txt":
            txt_path = base + "_alive.txt"
            save(results, txt_path, fmt="txt", alive_only=True)
            print(f"Plain-text alive list  → {txt_path}")


# ── Argument parser ─────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="socks5-toolkit",
        description="Scrape and verify free SOCKS5 proxies (RFC 1928 compliant).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py probe 1.2.3.4:1080
  python main.py check --input my_proxies.txt --out output/results.json
  python main.py scrape --out output/raw.txt
  python main.py scrape-check --workers 150 --timeout 4 --out output/alive.json --format json
        """,
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    sub = p.add_subparsers(dest="command")

    # ── probe ──
    sp = sub.add_parser("probe", help="Test a single proxy")
    sp.add_argument("proxy", help="host:port")
    sp.add_argument("-u", "--username", default=None)
    sp.add_argument("-p", "--password", default=None)
    sp.add_argument("--timeout", type=float, default=10.0)
    sp.add_argument("--test-host", default="httpbin.org")
    sp.add_argument("--test-port", type=int, default=80)

    # ── check ──
    sp = sub.add_parser("check", help="Bulk-check proxies from a file")
    sp.add_argument("-i", "--input", required=True, help="Path to proxy list file")
    sp.add_argument("-o", "--out", default=None, help="Output file path")
    sp.add_argument("-f", "--format", choices=["json", "csv", "txt", "auto"], default="auto")
    sp.add_argument("-w", "--workers", type=int, default=50)
    sp.add_argument("--timeout", type=float, default=5.0)
    sp.add_argument("--test-host", default="httpbin.org")
    sp.add_argument("--test-port", type=int, default=80)
    sp.add_argument("--all", action="store_true", help="Include dead proxies in output")
    sp.add_argument("-q", "--quiet", action="store_true", help="No table output")

    # ── scrape ──
    sp = sub.add_parser("scrape", help="Scrape free proxy lists (no check)")
    sp.add_argument("-o", "--out", default="output/raw.txt")
    sp.add_argument("--delay", type=float, default=0.5, help="Seconds between requests")

    # ── scrape-check ──
    sp = sub.add_parser("scrape-check", help="Scrape then check all proxies")
    sp.add_argument("-o", "--out", default="output/alive.txt")
    sp.add_argument("-f", "--format", choices=["json", "csv", "txt", "auto"], default="auto")
    sp.add_argument("-w", "--workers", type=int, default=100)
    sp.add_argument("--timeout", type=float, default=5.0)
    sp.add_argument("--test-host", default="httpbin.org")
    sp.add_argument("--test-port", type=int, default=80)
    sp.add_argument("--delay", type=float, default=0.5, help="Delay between scrape requests")
    sp.add_argument("--limit", type=int, default=None, help="Max proxies to check (random sample)")
    sp.add_argument("--all", action="store_true", help="Include dead proxies in output")
    sp.add_argument("-q", "--quiet", action="store_true", help="No table output")

    return p


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    setup_logging(args.verbose)

    dispatch = {
        "probe":         cmd_probe,
        "check":         cmd_check,
        "scrape":        cmd_scrape,
        "scrape-check":  cmd_scrape_check,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
