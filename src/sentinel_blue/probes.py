"""Scope-limited scorer-perspective service validation."""

from __future__ import annotations

import ipaddress
import http.client
import math
import secrets
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

from .protocol import ProbeResult


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a previously authorized IP while preserving the HTTP Host."""

    def __init__(self, host: str, pinned_ip: str, port: int, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    """HTTPS equivalent with certificate validation against the requested host."""

    def __init__(
        self,
        host: str,
        pinned_ip: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ):
        super().__init__(host, pinned_ip, port, timeout)
        self._context = context

    def connect(self) -> None:
        super().connect()
        assert self.sock is not None
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _port(value: Any) -> int:
    if type(value) is not int:
        raise ValueError("probe port must be an integer")
    result = value
    if not 1 <= result <= 65535:
        raise ValueError("probe port must be from 1 to 65535")
    return result


def _timeout(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("probe timeout must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("probe timeout must be finite")
    return max(0.2, min(result, 15.0))


def _boolean(spec: dict[str, Any], name: str, default: bool) -> bool:
    value = spec.get(name, default)
    if type(value) is not bool:
        raise ValueError(f"probe {name} must be a boolean")
    return value


def _text(value: Any, label: str, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value) or len(value) > limit:
        qualifier = "a bounded string" if empty else "a non-empty bounded string"
        raise ValueError(f"probe {label} must be {qualifier}")
    if "\x00" in value:
        raise ValueError(f"probe {label} contains a null byte")
    return value


def _receive_until(
    connection: socket.socket | ssl.SSLSocket,
    expected: bytes,
    limit: int = 4096,
) -> bytes:
    """Receive a bounded response while tolerating ordinary packet fragmentation."""
    if not expected:
        return b""
    received = bytearray()
    while len(received) < limit:
        chunk = connection.recv(min(1024, limit - len(received)))
        if not chunk:
            break
        received.extend(chunk)
        if expected in received:
            return bytes(received)
    raise RuntimeError("transaction response did not match within the receive limit")


def _dns_query(host: str, port: int, name: str, record_type: str, timeout: float) -> str:
    transaction = secrets.randbelow(65536)
    labels = name.rstrip(".").split(".")
    if (
        not labels
        or len(name.encode("idna")) > 253
        or any(not label or len(label.encode("idna")) > 63 for label in labels)
    ):
        raise ValueError("invalid DNS query name")
    question = b"".join(bytes([len(encoded)]) + encoded for encoded in (label.encode("idna") for label in labels)) + b"\x00"
    qtype = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16}.get(record_type.upper())
    if qtype is None:
        raise ValueError("DNS record_type must be A, AAAA, MX, or TXT")
    packet = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, 1)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        # A connected UDP socket accepts replies only from the exact address and
        # port that passed the authorization check.
        client.connect((host, port))
        client.send(packet)
        response = client.recv(4096)
    if len(response) < 12:
        raise RuntimeError("short DNS response")
    received, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
    if (
        received != transaction
        or not flags & 0x8000
        or flags & 0x7800
        or flags & 0x0200
        or questions != 1
    ):
        raise RuntimeError("invalid DNS response")
    rcode = flags & 0x000F
    if rcode != 0:
        raise RuntimeError(f"DNS response code {rcode}")
    if answers < int(1):
        raise RuntimeError("DNS response had no answers")
    return f"DNS {record_type.upper()} returned {answers} answer(s)"


def _addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return sorted({ipaddress.ip_address(item[4][0]) for item in answers}, key=str)


def scoped_addresses(
    host: str,
    authorized_networks: list[str],
    allow_loopback: bool = True,
    *,
    authorized_hosts: list[str] | tuple[str, ...] | None = None,
    excluded_hosts: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    """Return pinned addresses only when every DNS answer satisfies the full scope."""
    networks = [ipaddress.ip_network(value, strict=False) for value in authorized_networks]
    inventory = {
        ipaddress.ip_address(value) for value in (authorized_hosts or [])
    }
    exclusions = {
        ipaddress.ip_address(value) for value in (excluded_hosts or [])
    }
    legacy_loopback_scope = authorized_hosts is None and excluded_hosts is None
    addresses = _addresses(host)
    if not addresses:
        raise ValueError(f"target {host!r} did not resolve")
    for address in addresses:
        if address in exclusions:
            raise ValueError(f"target {address} is explicitly excluded")
        if not (
            legacy_loopback_scope and allow_loopback and address.is_loopback
        ) and not any(
            address in network for network in networks
        ):
            raise ValueError(f"target {address} is outside the authorized networks")
        if inventory and address not in inventory:
            raise ValueError(f"target {address} is not in the authorized host inventory")
    return [str(address) for address in addresses]


def validate_scope(
    host: str,
    authorized_networks: list[str],
    allow_loopback: bool = True,
    *,
    authorized_hosts: list[str] | tuple[str, ...] | None = None,
    excluded_hosts: list[str] | tuple[str, ...] | None = None,
) -> None:
    scoped_addresses(
        host,
        authorized_networks,
        allow_loopback,
        authorized_hosts=authorized_hosts,
        excluded_hosts=excluded_hosts,
    )


def _transaction_probe(
    spec: dict[str, Any], address: str, host: str, port: int, timeout: float
) -> str:
    """Run a bounded literal request/response script without invoking a shell."""
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > 8:
        raise ValueError("transaction steps must be an array of 1 to 8 objects")
    normalized: list[tuple[bytes, bytes]] = []
    total = 0
    for step in steps:
        if not isinstance(step, dict) or "send" not in step or "expect" not in step:
            raise ValueError("each transaction step requires send and expect")
        if not isinstance(step["send"], str) or not isinstance(step["expect"], str):
            raise ValueError("transaction send and expect values must be strings")
        send = step["send"].encode("utf-8")
        expect = step["expect"].encode("utf-8")
        if not send or not expect or len(send) > 1024 or len(expect) > 1024:
            raise ValueError("transaction send and expect values must be 1 to 1,024 bytes")
        total += len(send) + len(expect)
        normalized.append((send, expect))
    raw_initial = spec.get("initial_expected", "")
    if not isinstance(raw_initial, str):
        raise ValueError("transaction initial_expected must be a string")
    initial = raw_initial.encode("utf-8")
    total += len(initial)
    if len(initial) > 1024 or total > 8192:
        raise ValueError("transaction probe exceeds the 8,192-byte budget")
    use_tls = _boolean(spec, "tls", False)
    verify_tls = _boolean(spec, "verify", True)

    raw = socket.create_connection((address, port), timeout=timeout)
    connection: socket.socket | ssl.SSLSocket = raw
    try:
        raw.settimeout(timeout)
        if use_tls:
            context = ssl.create_default_context()
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            connection = context.wrap_socket(
                raw, server_hostname=str(spec.get("server_name", host))
            )
            connection.settimeout(timeout)
        if initial:
            _receive_until(connection, initial)
        for send, expect in normalized:
            connection.sendall(send)
            _receive_until(connection, expect)
    finally:
        connection.close()
    return f"application transaction completed {len(normalized)} step(s)"


def run_probe(
    spec: dict[str, Any],
    authorized_networks: list[str],
    *,
    authorized_hosts: list[str] | tuple[str, ...] | None = None,
    excluded_hosts: list[str] | tuple[str, ...] | None = None,
) -> ProbeResult:
    started = time.perf_counter()
    name = "unnamed-probe"
    target = "unknown"
    try:
        if not isinstance(spec, dict):
            raise ValueError("probe specification must be an object")
        name = _text(spec.get("name", spec.get("target", "unnamed-probe")), "name", 256)
        kind = _text(spec.get("kind", "tcp"), "kind", 32).casefold()
        target = _text(spec["target"], "target", 2048)
        timeout = _timeout(spec.get("timeout", 3.0))
        if kind == "tcp":
            host = _text(spec.get("host", target), "host", 253)
            port = _port(spec["port"])
            address = scoped_addresses(
                host,
                authorized_networks,
                authorized_hosts=authorized_hosts,
                excluded_hosts=excluded_hosts,
            )[0]
            with socket.create_connection((address, port), timeout=timeout):
                pass
            detail = "TCP connection succeeded"
        elif kind in {"http", "https"}:
            parsed = urlparse(target)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError("HTTP probe target must be an http(s) URL")
            address = scoped_addresses(
                parsed.hostname,
                authorized_networks,
                authorized_hosts=authorized_hosts,
                excluded_hosts=excluded_hosts,
            )[0]
            method = str(spec.get("method", "GET")).upper()
            if method not in {"GET", "HEAD"}:
                raise ValueError("only GET and HEAD probes are supported")
            expected = spec.get("expected_status", [200, 201, 202, 204, 301, 302, 401, 403])
            if not isinstance(expected, list) or not expected or len(expected) > 16:
                raise ValueError("expected_status must be an array of at most 16 status codes")
            if any(type(value) is not int for value in expected):
                raise ValueError("expected_status entries must be integers")
            expected_values = set(expected)
            if any(value < 100 or value > 599 for value in expected_values):
                raise ValueError("expected_status contains an invalid HTTP status code")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme == "https":
                context = ssl.create_default_context()
                if not _boolean(spec, "verify", True):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
                    parsed.hostname, address, port, timeout, context
                )
            else:
                connection = _PinnedHTTPConnection(parsed.hostname, address, port, timeout)
            request_path = parsed.path or "/"
            if parsed.query:
                request_path += f"?{parsed.query}"
            try:
                connection.request(
                    method,
                    request_path,
                    headers={"User-Agent": "Sentinel-Blue-Probe/1", "Connection": "close"},
                )
                response = connection.getresponse()
                status = int(response.status)
                if status not in expected_values:
                    raise RuntimeError(f"unexpected HTTP status {status}")
                expected_body = spec.get("expected_body")
                if expected_body is not None:
                    if not isinstance(expected_body, str):
                        raise ValueError("expected_body must be a string")
                    needle = expected_body.encode()
                    if not needle or len(needle) > 4096:
                        raise ValueError("expected_body must contain 1 to 4,096 bytes")
                    if needle not in response.read(65536):
                        raise RuntimeError("HTTP response did not contain expected_body")
                detail = f"HTTP {status}"
            finally:
                connection.close()
        elif kind == "dns":
            host = _text(spec.get("host", target), "host", 253)
            port = _port(spec.get("port", 53))
            host = scoped_addresses(
                host,
                authorized_networks,
                authorized_hosts=authorized_hosts,
                excluded_hosts=excluded_hosts,
            )[0]
            detail = _dns_query(
                host,
                port,
                _text(spec.get("query", "localhost"), "query", 253),
                _text(spec.get("record_type", "A"), "record_type", 16),
                timeout,
            )
        elif kind in {"banner", "smtp"}:
            host = _text(spec.get("host", target), "host", 253)
            port = _port(spec.get("port", 25 if kind == "smtp" else 1))
            host = scoped_addresses(
                host,
                authorized_networks,
                authorized_hosts=authorized_hosts,
                excluded_hosts=excluded_hosts,
            )[0]
            send_text = _text(
                spec.get("send", "EHLO sentinel-blue\r\n" if kind == "smtp" else ""),
                "send",
                1024,
                empty=True,
            )
            expected_text = _text(
                spec.get("expected", "220" if kind == "smtp" else ""),
                "expected",
                1024,
                empty=True,
            )
            send_bytes = send_text.encode()
            expected_bytes = expected_text.encode()
            if len(send_bytes) > 1024 or len(expected_bytes) > 1024:
                raise ValueError("banner probe text exceeds 1,024 bytes")
            with socket.create_connection((host, port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                banner = bytearray(connection.recv(4096))
                if send_bytes:
                    connection.sendall(send_bytes)
                while expected_bytes and expected_bytes not in banner and len(banner) < 8192:
                    chunk = connection.recv(min(4096, 8192 - len(banner)))
                    if not chunk:
                        break
                    banner.extend(chunk)
            decoded = banner.decode("utf-8", errors="replace")
            if expected_text and expected_text not in decoded:
                raise RuntimeError("service banner did not contain the expected text")
            detail = f"{kind.upper()} application response matched"
        elif kind == "tls":
            host = _text(spec.get("host", target), "host", 253)
            port = _port(spec.get("port", 443))
            address = scoped_addresses(
                host,
                authorized_networks,
                authorized_hosts=authorized_hosts,
                excluded_hosts=excluded_hosts,
            )[0]
            context = ssl.create_default_context()
            if not _boolean(spec, "verify", True):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((address, port), timeout=timeout) as raw:
                server_name = _text(spec.get("server_name", host), "server_name", 253)
                with context.wrap_socket(raw, server_hostname=server_name) as secured:
                    detail = f"TLS {secured.version()} handshake succeeded"
        elif kind == "transaction":
            host = _text(spec.get("host", target), "host", 253)
            port = _port(spec["port"])
            address = scoped_addresses(
                host,
                authorized_networks,
                authorized_hosts=authorized_hosts,
                excluded_hosts=excluded_hosts,
            )[0]
            detail = _transaction_probe(spec, address, host, port, timeout)
        else:
            raise ValueError(f"unsupported probe kind: {kind}")
        latency = round((time.perf_counter() - started) * 1000, 2)
        return ProbeResult(name=name, target=target, healthy=True, latency_ms=latency, detail=detail)
    except (KeyError, TypeError, OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
        latency = round((time.perf_counter() - started) * 1000, 2)
        return ProbeResult(name=name, target=target, healthy=False, latency_ms=latency, detail=str(exc))


def run_probes(
    specs: list[dict[str, Any]],
    authorized_networks: list[str],
    *,
    authorized_hosts: list[str] | tuple[str, ...] | None = None,
    excluded_hosts: list[str] | tuple[str, ...] | None = None,
) -> list[ProbeResult]:
    bounded = list(specs[:256])
    def run_scoped(spec: dict[str, Any]) -> ProbeResult:
        return run_probe(
            spec,
            authorized_networks,
            authorized_hosts=authorized_hosts,
            excluded_hosts=excluded_hosts,
        )

    if len(bounded) <= 1:
        return [run_scoped(spec) for spec in bounded]
    workers = min(16, len(bounded))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sentinel-probe") as pool:
        return list(pool.map(run_scoped, bounded))
