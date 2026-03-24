#!/usr/bin/env python3
"""
Tests for SOCKS5 toolkit.
Covers:
  - RFC 1928 packet construction
  - Parser correctness
  - Formatter outputs
  - Mock server handshake
"""

import io
import json
import socket
import struct
import threading
import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from socks5_checker import (
    SOCKS5Handshake, check_proxy, AuthMethod, Reply, REPLY_MESSAGES, ProxyResult
)
from scraper import _parse_text, _parse_html_table, _valid_entry
from formatters import to_json, to_csv, to_plain_text, summary


# ── Mock SOCKS5 server ────────────────────────────────────────────────────────

class MockSOCKS5Server(threading.Thread):
    """
    Minimal in-process SOCKS5 server used for unit testing.
    Supports NO_AUTH and USERNAME/PASSWORD, then always replies SUCCESS.
    """

    def __init__(self, host="127.0.0.1", auth_required=False,
                 reply_code=Reply.SUCCESS, username=None, password=None):
        super().__init__(daemon=True)
        self.host = host
        self.auth_required = auth_required
        self.reply_code = reply_code
        self.expected_username = username
        self.expected_password = password
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self.ready = threading.Event()

    def run(self):
        self.ready.set()
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(5)
            self._handle(conn)
        except Exception:
            pass
        finally:
            try:
                self.sock.close()
            except Exception:
                pass

    def _recv_exact(self, conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf

    def _handle(self, conn):
        # Step 1: Client Negotiation
        ver_nmeth = self._recv_exact(conn, 2)
        ver, nmeth = struct.unpack("BB", ver_nmeth)
        methods = self._recv_exact(conn, nmeth)

        # Step 2: Server Negotiation
        if self.auth_required:
            if AuthMethod.USERNAME in methods:
                conn.sendall(struct.pack("BB", 5, AuthMethod.USERNAME))
                # RFC 1929 username/password exchange
                auth_ver = self._recv_exact(conn, 1)[0]
                ulen = self._recv_exact(conn, 1)[0]
                uname = self._recv_exact(conn, ulen).decode()
                plen = self._recv_exact(conn, 1)[0]
                passwd = self._recv_exact(conn, plen).decode()
                ok = (uname == self.expected_username and passwd == self.expected_password)
                conn.sendall(struct.pack("BB", 1, 0 if ok else 1))
                if not ok:
                    conn.close()
                    return
            else:
                conn.sendall(struct.pack("BB", 5, AuthMethod.NO_ACCEPT))
                conn.close()
                return
        else:
            conn.sendall(struct.pack("BB", 5, AuthMethod.NO_AUTH))

        # Step 3: Client Request
        header = self._recv_exact(conn, 4)
        ver, cmd, rsv, atyp = struct.unpack("BBBB", header)
        if atyp == 1:  # IPv4
            self._recv_exact(conn, 4 + 2)
        elif atyp == 3:  # Domain
            dlen = self._recv_exact(conn, 1)[0]
            self._recv_exact(conn, dlen + 2)
        elif atyp == 4:  # IPv6
            self._recv_exact(conn, 16 + 2)

        # Step 4: Server Reply
        rep = int(self.reply_code)
        reply = struct.pack("BBBB", 5, rep, 0, 1) + b"\x00" * 4 + struct.pack(">H", 0)
        conn.sendall(reply)
        conn.close()


# ── Tests ────────────────────────────────────────────────────────────────────

class TestSOCKS5Handshake(unittest.TestCase):

    def _start_server(self, **kwargs):
        srv = MockSOCKS5Server(**kwargs)
        srv.start()
        srv.ready.wait(2)
        return srv

    def test_no_auth_success(self):
        srv = self._start_server()
        alive, lat, rep, err = SOCKS5Handshake(
            srv.host, srv.port, timeout=3
        ).check("example.com", 80)
        self.assertTrue(alive, f"Expected alive but got: {err}")
        self.assertEqual(rep, Reply.SUCCESS)
        self.assertGreater(lat, 0)

    def test_auth_success(self):
        srv = self._start_server(
            auth_required=True, username="alice", password="secret"
        )
        alive, lat, rep, err = SOCKS5Handshake(
            srv.host, srv.port,
            username="alice", password="secret",
            timeout=3
        ).check("example.com", 80)
        self.assertTrue(alive, f"Expected alive but got: {err}")

    def test_auth_wrong_password(self):
        srv = self._start_server(
            auth_required=True, username="alice", password="secret"
        )
        alive, lat, rep, err = SOCKS5Handshake(
            srv.host, srv.port,
            username="alice", password="WRONG",
            timeout=3
        ).check("example.com", 80)
        self.assertFalse(alive)

    def test_conn_refused(self):
        alive, lat, rep, err = SOCKS5Handshake(
            "127.0.0.1", 19999, timeout=2
        ).check("example.com", 80)
        self.assertFalse(alive)
        self.assertIn("refused", err.lower())

    def test_proxy_returns_error_reply(self):
        srv = self._start_server(reply_code=Reply.CONN_REFUSED)
        alive, lat, rep, err = SOCKS5Handshake(
            srv.host, srv.port, timeout=3
        ).check("example.com", 80)
        self.assertFalse(alive)
        self.assertEqual(rep, Reply.CONN_REFUSED)

    def test_timeout(self):
        # Bind a port but never accept to simulate timeout
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # close so it's unreachable — OS may give refused instead
        alive, lat, rep, err = SOCKS5Handshake(
            "127.0.0.1", port, timeout=0.5
        ).check("example.com", 80)
        self.assertFalse(alive)


class TestParser(unittest.TestCase):

    def test_parse_text_basic(self):
        data = "1.2.3.4:1080\n5.6.7.8:1080\n"
        proxies = _parse_text(data)
        self.assertIn(("1.2.3.4", 1080), proxies)
        self.assertIn(("5.6.7.8", 1080), proxies)

    def test_parse_text_filters_private(self):
        data = "10.0.0.1:1080\n192.168.1.1:1080\n172.16.0.1:1080\n"
        proxies = _parse_text(data)
        self.assertEqual(len(proxies), 0)

    def test_parse_html_table(self):
        html = "<tr><td>8.8.8.8</td><td>1080</td></tr>"
        proxies = _parse_html_table(html)
        self.assertIn(("8.8.8.8", 1080), proxies)

    def test_valid_entry(self):
        self.assertTrue(_valid_entry("8.8.8.8", 1080))
        self.assertFalse(_valid_entry("10.0.0.1", 1080))
        self.assertFalse(_valid_entry("127.0.0.1", 1080))
        self.assertFalse(_valid_entry("192.168.1.1", 1080))
        self.assertFalse(_valid_entry("8.8.8.8", 0))
        self.assertFalse(_valid_entry("8.8.8.8", 99999))

    def test_parse_weird_separators(self):
        data = "1.2.3.4 1080\n5.6.7.8,1080\n9.10.11.12|1080\n"
        proxies = _parse_text(data)
        self.assertIn(("1.2.3.4", 1080), proxies)
        self.assertIn(("5.6.7.8", 1080), proxies)
        self.assertIn(("9.10.11.12", 1080), proxies)


class TestFormatters(unittest.TestCase):

    def _make_results(self):
        r1 = ProxyResult(host="1.2.3.4", port=1080, alive=True,  latency_ms=120.5)
        r2 = ProxyResult(host="5.6.7.8", port=1080, alive=False, error="Timeout")
        return [r1, r2]

    def test_to_plain_text_alive_only(self):
        results = self._make_results()
        txt = to_plain_text(results, alive_only=True)
        self.assertIn("1.2.3.4:1080", txt)
        self.assertNotIn("5.6.7.8", txt)

    def test_to_json(self):
        results = self._make_results()
        data = json.loads(to_json(results, alive_only=False))
        self.assertEqual(len(data), 2)
        self.assertTrue(data[0]["alive"])
        self.assertFalse(data[1]["alive"])

    def test_to_csv(self):
        results = self._make_results()
        csv_data = to_csv(results, alive_only=False)
        self.assertIn("host", csv_data)
        self.assertIn("1.2.3.4", csv_data)
        self.assertIn("5.6.7.8", csv_data)

    def test_summary(self):
        results = self._make_results()
        s = summary(results)
        self.assertIn("Total checked", s)
        self.assertIn("Alive", s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
