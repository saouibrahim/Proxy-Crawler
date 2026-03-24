#!/usr/bin/env python3
"""
Output formatters for SOCKS5 toolkit results.
Supports JSON, CSV, plain-text (host:port) and a human-readable table.
"""

import csv
import json
import io
import os
from typing import List
from socks5_checker import ProxyResult


# ── Plain-text (host:port) ────────────────────────────────────────────────────

def to_plain_text(results: List[ProxyResult], alive_only: bool = True) -> str:
    lines = []
    for r in results:
        if alive_only and not r.alive:
            continue
        lines.append(f"{r.host}:{r.port}")
    return "\n".join(lines)


# ── CSV ───────────────────────────────────────────────────────────────────────

def to_csv(results: List[ProxyResult], alive_only: bool = False) -> str:
    buf = io.StringIO()
    fieldnames = ["host", "port", "alive", "latency_ms", "country",
                  "username", "password", "reply_code", "error", "checked_at"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        if alive_only and not r.alive:
            continue
        writer.writerow(r.to_dict())
    return buf.getvalue()


# ── JSON ──────────────────────────────────────────────────────────────────────

def to_json(results: List[ProxyResult], alive_only: bool = False, indent: int = 2) -> str:
    data = [r.to_dict() for r in results if not alive_only or r.alive]
    return json.dumps(data, indent=indent, ensure_ascii=False)


# ── Pretty table ──────────────────────────────────────────────────────────────

def to_table(results: List[ProxyResult], alive_only: bool = True, max_rows: int = 200) -> str:
    rows = [r for r in results if not alive_only or r.alive][:max_rows]
    if not rows:
        return "(no results)"

    col_host    = max(len("HOST"),    max(len(r.host) for r in rows))
    col_port    = 6
    col_latency = 12
    col_status  = 8
    col_error   = 32

    sep = (
        "+" + "-" * (col_host + 2) +
        "+" + "-" * (col_port + 2) +
        "+" + "-" * (col_latency + 2) +
        "+" + "-" * (col_status + 2) +
        "+" + "-" * (col_error + 2) +
        "+"
    )
    hdr = (
        f"| {'HOST':<{col_host}} | {'PORT':<{col_port}} | "
        f"{'LATENCY (ms)':<{col_latency}} | {'STATUS':<{col_status}} | "
        f"{'ERROR':<{col_error}} |"
    )

    lines = [sep, hdr, sep]
    for r in rows:
        status = "✓ OK" if r.alive else "✗ FAIL"
        latency = f"{r.latency_ms:.1f}" if r.latency_ms >= 0 else "—"
        error = (r.error or "")[:col_error]
        line = (
            f"| {r.host:<{col_host}} | {r.port:<{col_port}} | "
            f"{latency:<{col_latency}} | {status:<{col_status}} | "
            f"{error:<{col_error}} |"
        )
        lines.append(line)
    lines.append(sep)
    return "\n".join(lines)


# ── Summary stats ──────────────────────────────────────────────────────────────

def summary(results: List[ProxyResult]) -> str:
    total = len(results)
    alive = sum(1 for r in results if r.alive)
    dead  = total - alive
    latencies = [r.latency_ms for r in results if r.alive and r.latency_ms > 0]
    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    min_lat = min(latencies) if latencies else 0
    max_lat = max(latencies) if latencies else 0
    pct = (alive / total * 100) if total else 0

    lines = [
        "┌─────────────────────────────────────┐",
        "│          CHECK SUMMARY              │",
        "├─────────────────────────────────────┤",
        f"│  Total checked : {total:<18} │",
        f"│  Alive         : {alive:<18} │",
        f"│  Dead          : {dead:<18} │",
        f"│  Success rate  : {pct:>7.1f} %          │",
        "├─────────────────────────────────────┤",
        f"│  Avg latency   : {avg_lat:>7.1f} ms         │",
        f"│  Min latency   : {min_lat:>7.1f} ms         │",
        f"│  Max latency   : {max_lat:>7.1f} ms         │",
        "└─────────────────────────────────────┘",
    ]
    return "\n".join(lines)


# ── File writers ──────────────────────────────────────────────────────────────

def save(results: List[ProxyResult], path: str, fmt: str = "auto", alive_only: bool = True):
    """
    Save results to a file.
    fmt: 'json' | 'csv' | 'txt' | 'auto' (infer from extension)
    """
    if fmt == "auto":
        ext = os.path.splitext(path)[1].lower()
        fmt = {"json": "json", ".csv": "csv", ".txt": "txt"}.get(ext, "txt")

    if fmt == "json":
        content = to_json(results, alive_only=alive_only)
    elif fmt == "csv":
        content = to_csv(results, alive_only=alive_only)
    else:
        content = to_plain_text(results, alive_only=alive_only)

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
