"""Shared strict URL-origin validation for authenticated control traffic."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_http_origin(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("controller must be a bounded http(s) origin")
    if any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise ValueError("controller origin contains unsafe characters")
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("controller must be a simple http(s) origin without credentials or a path")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("controller origin has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("controller origin has an invalid port")
    hostname = parsed.hostname.rstrip(".")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            encoded = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("controller origin has an invalid hostname") from exc
        labels = encoded.split(".")
        if len(encoded) > 253 or not labels or any(not DNS_LABEL.fullmatch(label) for label in labels):
            raise ValueError("controller origin has an invalid hostname")
    return value.rstrip("/")


__all__ = ["validate_http_origin"]
