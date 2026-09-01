"""Strict, bounded JSON codec for authenticated wire and persisted data.

The standard library decoder intentionally accepts several JavaScript extensions
(``NaN``/``Infinity``) and silently keeps the last duplicate object key.  Neither
behaviour is suitable for signed protocol messages or security state.  All JSON
crossing those trust boundaries goes through this module.
"""

from __future__ import annotations

import json
import math
from typing import Any


MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_JSON_CONTAINER_ITEMS = 16_384
MAX_JSON_STRING_CHARS = 262_144
MAX_JSON_TOTAL_STRING_CHARS = 1_000_000


class StrictJsonError(ValueError):
    """Raised when JSON is not strict UTF-8 or exceeds structural bounds."""


def _reject_constant(value: str) -> Any:
    raise StrictJsonError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(f"duplicate JSON object key: {key[:64]}")
        result[key] = value
    return result


def validate_json_value(
    value: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
    max_container_items: int = MAX_JSON_CONTAINER_ITEMS,
    max_string_chars: int = MAX_JSON_STRING_CHARS,
    max_total_string_chars: int = MAX_JSON_TOTAL_STRING_CHARS,
) -> Any:
    """Validate a JSON-compatible value iteratively and return it unchanged."""
    if min(
        max_depth,
        max_nodes,
        max_container_items,
        max_string_chars,
        max_total_string_chars,
    ) < 1:
        raise ValueError("JSON limits must be positive")
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    string_chars = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise StrictJsonError("JSON exceeds the node limit")
        if depth > max_depth:
            raise StrictJsonError("JSON exceeds the nesting-depth limit")
        if item is None or type(item) is bool:
            continue
        if type(item) is int:
            if not -(2**63) <= item <= 2**63 - 1:
                raise StrictJsonError(
                    "JSON integer is outside the signed 64-bit range"
                )
            continue
        if type(item) is float:
            if not math.isfinite(item):
                raise StrictJsonError("non-finite JSON numbers are forbidden")
            continue
        if isinstance(item, str):
            if len(item) > max_string_chars:
                raise StrictJsonError("JSON string exceeds the per-string limit")
            try:
                item.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise StrictJsonError("JSON string contains invalid Unicode") from exc
            string_chars += len(item)
            if string_chars > max_total_string_chars:
                raise StrictJsonError("JSON exceeds the total string budget")
            continue
        if isinstance(item, (list, tuple)):
            if len(item) > max_container_items:
                raise StrictJsonError("JSON array exceeds the item limit")
            stack.extend((child, depth + 1) for child in item)
            continue
        if isinstance(item, dict):
            if len(item) > max_container_items:
                raise StrictJsonError("JSON object exceeds the item limit")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise StrictJsonError("JSON object keys must be strings")
                if len(key) > max_string_chars:
                    raise StrictJsonError("JSON object key exceeds the string limit")
                try:
                    key.encode("utf-8", "strict")
                except UnicodeEncodeError as exc:
                    raise StrictJsonError(
                        "JSON object key contains invalid Unicode"
                    ) from exc
                string_chars += len(key)
                if string_chars > max_total_string_chars:
                    raise StrictJsonError("JSON exceeds the total string budget")
                stack.append((child, depth + 1))
            continue
        raise StrictJsonError(f"value of type {type(item).__name__} is not JSON")
    return value


def strict_json_loads(data: bytes | bytearray | memoryview | str, *, max_bytes: int) -> Any:
    """Decode one strict UTF-8 JSON document within byte/structure limits."""
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if isinstance(data, str):
        if data.startswith("\ufeff"):
            raise StrictJsonError("JSON must not contain a byte-order mark")
        try:
            encoded = data.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise StrictJsonError("JSON contains invalid Unicode") from exc
        if len(encoded) > max_bytes:
            raise StrictJsonError("JSON exceeds the byte limit")
        text = data
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
        if len(raw) > max_bytes:
            raise StrictJsonError("JSON exceeds the byte limit")
        if raw.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            raise StrictJsonError("JSON must be UTF-8 without a byte-order mark")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise StrictJsonError("JSON is not valid UTF-8") from exc
    else:
        raise StrictJsonError("JSON input must be bytes or text")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except StrictJsonError:
        raise
    except (ValueError, RecursionError) as exc:
        raise StrictJsonError(f"invalid JSON: {exc}") from exc
    return validate_json_value(value)


def canonical_json_dumps(value: Any, *, max_bytes: int | None = None) -> str:
    """Serialize bounded JSON deterministically; never coerce unsupported values."""
    validate_json_value(value)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise StrictJsonError(f"value is not canonical JSON: {exc}") from exc
    if max_bytes is not None and len(encoded) > max_bytes:
        raise StrictJsonError("encoded JSON exceeds the byte limit")
    return encoded.decode("utf-8")


def canonical_json_bytes(value: Any, *, max_bytes: int | None = None) -> bytes:
    """Return deterministic UTF-8 JSON bytes."""
    return canonical_json_dumps(value, max_bytes=max_bytes).encode("utf-8")
