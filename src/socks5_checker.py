#!/usr/bin/env python3
"""
SOCKS5 Proxy Checker
====================
Validates SOCKS5 proxies by performing the full RFC 1928 handshake:
  1. Client Negotiation  (VER=5, NMETHODS, METHODS)
  2. Server Negotiation  (VER=5, METHOD chosen)
  3. Client Request      (CONNECT to test host)
  4. Server Reply        (REP=0x00 means success)

No external dependencies — pure Python stdlib.
"""

import socket
import struct
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from enum import IntEnum

logger = logging.getLogger(__name__)

# ── RFC 1928 constants ──────────────────────────────────────────────────────

class AuthMethod(IntEnum):
    NO_AUTH   = 0x00
    GSSAPI    = 0x01
    USERNAME  = 0x02
    NO_ACCEPT = 0xFF

class AddrType(IntEnum):
    IPV4   = 0x01
    DOMAIN = 0x03
    IPV6   = 0x04

class Command(IntEnum):
    CONNECT       = 0x01
    BIND          = 0x02
    UDP_ASSOCIATE = 0x03

class Reply(IntEnum):
    SUCCESS              = 0x00
    GENERAL_FAILURE      = 0x01
    CONN_NOT_ALLOWED     = 0x02
    NETWORK_UNREACHABLE  = 0x03
    HOST_UNREACHABLE     = 0x04
    CONN_REFUSED         = 0x05
    TTL_EXPIRED          = 0x06
    CMD_NOT_SUPPORTED    = 0x07
    ADDR_NOT_SUPPORTED   = 0x08

REPLY_MESSAGES = {
    0x00: "Success",
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported",
    0x08: "Address type not supported",
}

# ── Data models ─────────────────────────────────────────────────────────────

@dataclass
class ProxyResult:
    host: str
    port: int
    alive: bool = False
    latency_ms: float = -1.0
    country: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    reply_code: int = -1
    error: str = ""
    checked_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "alive": self.alive,
            "latency_ms": round(self.latency_ms, 2),
            "country": self.country,
            "username": self.username or "",
            "password": self.password or "",
            "reply_code": self.reply_code,
            "error": self.error,
            "checked_at": self.checked_at,
        }

# ── Core SOCKS5 handshake ────────────────────────────────────────────────────

class SOCKS5Handshake:
    """
    Implements the full SOCKS5 negotiation as per RFC 1928 / RFC 1929.

    Packet layout reference (from the project documents):

    Client Negotiation:  VER(1) | NMETHODS(1) | METHODS(n)
    Server Negotiation:  VER(1) | METHOD(1)
    Client Request:      VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2)
    Server Reply:        VER(1) | REP(1) | RSV(1) | ATYP(1) | BND.ADDR | BND.PORT(2)
    """

    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.timeout = timeout

    def _send_recv(self, sock: socket.socket, data: bytes, expect: int) -> bytes:
        sock.sendall(data)
        buf = b""
        while len(buf) < expect:
            chunk = sock.recv(expect - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed by proxy")
            buf += chunk
        return buf

    def _negotiate_auth(self, sock: socket.socket) -> AuthMethod:
        """Step 1+2: Method negotiation."""
        methods = [AuthMethod.NO_AUTH]
        if self.username is not None:
            methods = [AuthMethod.USERNAME, AuthMethod.NO_AUTH]

        # Client Negotiation: VER=5, NMETHODS, METHODS
        pkt = struct.pack("BB", 0x05, len(methods)) + bytes(methods)
        sock.sendall(pkt)

        # Server Negotiation: VER, METHOD
        resp = self._recv_exact(sock, 2)
        ver, method = struct.unpack("BB", resp)
        if ver != 0x05:
            raise ValueError(f"Server returned unexpected SOCKS version: {ver}")
        if method == AuthMethod.NO_ACCEPT:
            raise PermissionError("Proxy rejected all authentication methods")
        return AuthMethod(method)

    def _authenticate(self, sock: socket.socket, method: AuthMethod) -> None:
        """Step 3: Authenticate using the negotiated method (RFC 1929 username/password)."""
        if method == AuthMethod.NO_AUTH:
            return
        if method == AuthMethod.USERNAME:
            if not self.username or not self.password:
                raise ValueError("Proxy requires username/password but none provided")
            u = self.username.encode()
            p = self.password.encode()
            # RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD
            pkt = struct.pack("BB", 0x01, len(u)) + u + struct.pack("B", len(p)) + p
            sock.sendall(pkt)
            resp = self._recv_exact(sock, 2)
            _, status = struct.unpack("BB", resp)
            if status != 0x00:
                raise PermissionError(f"Authentication failed (status={status})")
        else:
            raise NotImplementedError(f"Auth method {method} not implemented (GSSAPI requires krb5)")

    def _send_connect(self, sock: socket.socket, target_host: str, target_port: int) -> int:
        """Step 4+5: Send CONNECT request, return REP code."""
        # Determine address type
        try:
            socket.inet_pton(socket.AF_INET, target_host)
            atyp = AddrType.IPV4
            addr_bytes = socket.inet_aton(target_host)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, target_host)
                atyp = AddrType.IPV6
                addr_bytes = socket.inet_pton(socket.AF_INET6, target_host)
            except OSError:
                # Domain name
                atyp = AddrType.DOMAIN
                enc = target_host.encode()
                addr_bytes = struct.pack("B", len(enc)) + enc

        # Client Request: VER CMD RSV ATYP ADDR PORT
        pkt = struct.pack("BBBB", 0x05, Command.CONNECT, 0x00, int(atyp))
        pkt += addr_bytes
        pkt += struct.pack(">H", target_port)
        sock.sendall(pkt)

        # Server Reply: VER REP RSV ATYP ...
        header = self._recv_exact(sock, 4)
        ver, rep, _, atyp_resp = struct.unpack("BBBB", header)
        if ver != 0x05:
            raise ValueError(f"Unexpected SOCKS version in reply: {ver}")

        # Consume the BND.ADDR and BND.PORT so the socket is clean
        if atyp_resp == AddrType.IPV4:
            self._recv_exact(sock, 4 + 2)
        elif atyp_resp == AddrType.IPV6:
            self._recv_exact(sock, 16 + 2)
        elif atyp_resp == AddrType.DOMAIN:
            dlen = struct.unpack("B", self._recv_exact(sock, 1))[0]
            self._recv_exact(sock, dlen + 2)

        return rep

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed by proxy")
            buf += chunk
        return buf

    def check(
        self,
        test_host: str = "httpbin.org",
        test_port: int = 80,
    ) -> Tuple[bool, float, int, str]:
        """
        Perform the full SOCKS5 handshake.

        Returns:
            (success, latency_ms, reply_code, error_message)
        """
        t0 = time.monotonic()
        try:
            with socket.create_connection(
                (self.proxy_host, self.proxy_port), timeout=self.timeout
            ) as sock:
                sock.settimeout(self.timeout)
                method = self._negotiate_auth(sock)
                self._authenticate(sock, method)
                rep = self._send_connect(sock, test_host, test_port)
                latency_ms = (time.monotonic() - t0) * 1000
                success = rep == Reply.SUCCESS
                msg = REPLY_MESSAGES.get(rep, f"Unknown reply code {rep:#04x}")
                return success, latency_ms, rep, ("" if success else msg)
        except (socket.timeout, TimeoutError):
            return False, -1.0, -1, "Connection timed out"
        except ConnectionRefusedError:
            return False, -1.0, -1, "Connection refused"
        except PermissionError as e:
            return False, -1.0, -1, str(e)
        except Exception as e:
            return False, -1.0, -1, str(e)


# ── Bulk checker ─────────────────────────────────────────────────────────────

def check_proxy(
    host: str,
    port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 5.0,
    test_host: str = "httpbin.org",
    test_port: int = 80,
) -> ProxyResult:
    result = ProxyResult(host=host, port=port, username=username, password=password)
    hs = SOCKS5Handshake(host, port, username, password, timeout)
    alive, latency, rep, err = hs.check(test_host, test_port)
    result.alive = alive
    result.latency_ms = latency
    result.reply_code = rep
    result.error = err
    return result


def check_proxies_bulk(
    proxies: List[Tuple],
    workers: int = 50,
    timeout: float = 5.0,
    test_host: str = "httpbin.org",
    test_port: int = 80,
    on_result=None,
) -> List[ProxyResult]:
    """
    Check a list of proxies concurrently.

    proxies: list of (host, port) or (host, port, username, password)
    on_result: optional callback(ProxyResult) called as each result arrives
    """
    results = []
    lock = threading.Lock()

    def worker(entry):
        if len(entry) == 2:
            host, port = entry
            user = pwd = None
        else:
            host, port, user, pwd = entry[:4]
        r = check_proxy(host, port, user, pwd, timeout, test_host, test_port)
        with lock:
            results.append(r)
        if on_result:
            on_result(r)
        return r

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(worker, p): p for p in proxies}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                logger.warning("Worker exception: %s", e)

    return sorted(results, key=lambda r: (not r.alive, r.latency_ms))
