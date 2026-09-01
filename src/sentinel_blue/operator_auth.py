"""Strict request signing primitives for the operator HTTP control plane.

The long-lived operator secret is a signing key, never a reusable bearer.  This
module deliberately does not own replay persistence: a controller must verify a
request here and then durably admit the returned request identifier before it
performs any side effect.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import math
import re
import time
from collections.abc import Mapping
from typing import Any

from .auth import ENROLLMENT_TOKEN


OPERATOR_AUTH_VERSION = "1"
OPERATOR_AUTH_DOMAIN = b"sentinel-blue-operator-request-v1"
OPERATOR_KEY_FINGERPRINT_DOMAIN = b"sentinel-blue-operator-key-fingerprint-v1\x00"
OPERATOR_MAX_CLOCK_SKEW_SECONDS = 300
OPERATOR_MAX_TARGET_BYTES = 2048

OPERATOR_HEADER_VERSION = "X-SB-Operator-Version"
OPERATOR_HEADER_PRINCIPAL = "X-SB-Operator-Principal"
OPERATOR_HEADER_EPOCH = "X-SB-Operator-Epoch"
OPERATOR_HEADER_TIMESTAMP = "X-SB-Operator-Timestamp"
OPERATOR_HEADER_REQUEST_ID = "X-SB-Operator-Request-ID"
OPERATOR_HEADER_SIGNATURE = "X-SB-Operator-Signature"
LEGACY_OPERATOR_HEADER = "X-SB-Operator"

OPERATOR_SIGNING_HEADERS = (
    OPERATOR_HEADER_VERSION,
    OPERATOR_HEADER_PRINCIPAL,
    OPERATOR_HEADER_EPOCH,
    OPERATOR_HEADER_TIMESTAMP,
    OPERATOR_HEADER_REQUEST_ID,
    OPERATOR_HEADER_SIGNATURE,
)

OPERATOR_PRINCIPAL_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
CANONICAL_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]{0,18})$")
OPERATOR_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
OPERATOR_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
HTTP_METHOD = re.compile(r"^[A-Z]{1,16}$")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class OperatorHeaderError(ValueError):
    """The operator authentication header set is missing or non-canonical."""


class OperatorAuthenticationError(ValueError):
    """The operator request could not be authenticated."""


@dataclass(frozen=True, slots=True)
class OperatorRequestHeaders:
    """Structurally valid, but not yet authenticated, operator headers."""

    principal_id: str
    credential_epoch: int
    request_timestamp: int
    request_id: str
    supplied_signature: str
    version: str = OPERATOR_AUTH_VERSION


@dataclass(frozen=True, slots=True)
class OperatorRequestContext:
    """Immutable identity and replay binding for one verified request."""

    principal_id: str
    credential_epoch: int
    request_timestamp: int
    request_id: str
    supplied_signature: str

    @property
    def marker_sha256(self) -> str:
        """Return a non-secret durable marker for this exact signature."""
        return hashlib.sha256(self.supplied_signature.encode("ascii")).hexdigest()


def _validate_secret(token: str) -> bytes:
    if not isinstance(token, str) or not ENROLLMENT_TOKEN.fullmatch(token):
        raise ValueError(
            "operator signing requires a 32-256 character URL-safe secret"
        )
    return token.encode("ascii")


def validate_operator_principal(principal_id: object) -> str:
    if not isinstance(principal_id, str) or not OPERATOR_PRINCIPAL_ID.fullmatch(
        principal_id
    ):
        raise ValueError("operator principal identifier is invalid")
    return principal_id


def _canonical_integer(value: object, label: str, *, minimum: int) -> tuple[int, str]:
    if type(value) is int:
        parsed = value
        encoded = str(value)
    elif isinstance(value, str) and CANONICAL_DECIMAL.fullmatch(value):
        encoded = value
        parsed = int(value)
    else:
        raise ValueError(f"{label} is not a canonical decimal integer")
    if not minimum <= parsed <= 2**63 - 1 or str(parsed) != encoded:
        raise ValueError(f"{label} is outside its supported range")
    return parsed, encoded


def _validate_request_id(request_id: object) -> str:
    if not isinstance(request_id, str) or not OPERATOR_REQUEST_ID.fullmatch(
        request_id
    ):
        raise ValueError("operator request identifier is invalid")
    return request_id


def _validate_method(method: object) -> str:
    if not isinstance(method, str) or not HTTP_METHOD.fullmatch(method):
        raise ValueError("operator request method is invalid or non-canonical")
    return method


def _validate_target(target: object) -> str:
    if not isinstance(target, str):
        raise ValueError("operator request target must be a string")
    try:
        encoded = target.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("operator request target must be ASCII origin-form") from exc
    if (
        not encoded
        or len(encoded) > OPERATOR_MAX_TARGET_BYTES
        or not target.startswith("/")
        or target.startswith("//")
        or "#" in target
        or "\\" in target
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in target)
    ):
        raise ValueError("operator request target is not strict origin-form")
    for index, character in enumerate(target):
        if character == "%" and (
            index + 2 >= len(target)
            or target[index + 1] not in HEX_DIGITS
            or target[index + 2] not in HEX_DIGITS
        ):
            raise ValueError("operator request target contains invalid percent encoding")
    return target


def operator_key_fingerprint(token: str) -> str:
    """Bind persistent controller state to the configured operator key."""
    return hmac.new(
        _validate_secret(token), OPERATOR_KEY_FINGERPRINT_DOMAIN, hashlib.sha256
    ).hexdigest()


def operator_canonical_bytes(
    principal_id: str,
    credential_epoch: int | str,
    request_timestamp: int | str,
    request_id: str,
    method: str,
    target: str,
    body: bytes,
) -> bytes:
    """Build the exact cross-language version-one signing transcript."""
    principal = validate_operator_principal(principal_id)
    _epoch, epoch_text = _canonical_integer(
        credential_epoch, "operator credential epoch", minimum=1
    )
    _timestamp, timestamp_text = _canonical_integer(
        request_timestamp, "operator request timestamp", minimum=0
    )
    nonce = _validate_request_id(request_id)
    canonical_method = _validate_method(method)
    canonical_target = _validate_target(target)
    if not isinstance(body, bytes):
        raise ValueError("operator request body must be exact bytes")
    fields = (
        OPERATOR_AUTH_DOMAIN,
        principal.encode("ascii"),
        epoch_text.encode("ascii"),
        timestamp_text.encode("ascii"),
        nonce.encode("ascii"),
        canonical_method.encode("ascii"),
        canonical_target.encode("ascii"),
        hashlib.sha256(body).hexdigest().encode("ascii"),
    )
    return b"\x00".join(fields)


def operator_signature(
    token: str,
    principal_id: str,
    credential_epoch: int | str,
    request_timestamp: int | str,
    request_id: str,
    method: str,
    target: str,
    body: bytes,
) -> str:
    """Sign an exact operator HTTP request with HMAC-SHA256."""
    canonical = operator_canonical_bytes(
        principal_id,
        credential_epoch,
        request_timestamp,
        request_id,
        method,
        target,
        body,
    )
    return hmac.new(_validate_secret(token), canonical, hashlib.sha256).hexdigest()


def verify_operator_request(
    token: str,
    principal_id: str,
    credential_epoch: int | str,
    request_timestamp: int | str,
    request_id: str,
    method: str,
    target: str,
    body: bytes,
    supplied_signature: str,
    *,
    expected_principal: str | None = None,
    expected_credential_epoch: int | None = None,
    max_clock_skew: float = OPERATOR_MAX_CLOCK_SKEW_SECONDS,
    now: float | None = None,
) -> bool:
    """Verify request integrity, freshness, and the configured authority binding."""
    try:
        if isinstance(max_clock_skew, bool) or isinstance(now, bool):
            return False
        if not isinstance(supplied_signature, str) or not OPERATOR_SIGNATURE.fullmatch(
            supplied_signature
        ):
            return False
        principal = validate_operator_principal(principal_id)
        epoch, epoch_text = _canonical_integer(
            credential_epoch, "operator credential epoch", minimum=1
        )
        timestamp, timestamp_text = _canonical_integer(
            request_timestamp, "operator request timestamp", minimum=0
        )
        current = float(time.time() if now is None else now)
        skew = float(max_clock_skew)
        if (
            not math.isfinite(current)
            or not 0 <= current <= 2**63 - 1
            or not math.isfinite(skew)
            or skew < 1.0
            or abs(current - timestamp) > skew
        ):
            return False
        if expected_principal is not None and not hmac.compare_digest(
            principal, validate_operator_principal(expected_principal)
        ):
            return False
        if expected_credential_epoch is not None and (
            type(expected_credential_epoch) is not int
            or expected_credential_epoch < 1
            or epoch != expected_credential_epoch
        ):
            return False
        expected = operator_signature(
            token,
            principal,
            epoch_text,
            timestamp_text,
            request_id,
            method,
            target,
            body,
        )
    except (TypeError, ValueError, UnicodeError, OverflowError):
        return False
    return hmac.compare_digest(expected, supplied_signature)


def _header_values(headers: Any, name: str) -> list[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter(name) or []
        return list(values)
    if isinstance(headers, Mapping):
        values: list[str] = []
        folded = name.casefold()
        for key, value in headers.items():
            if isinstance(key, str) and key.casefold() == folded:
                values.append(value)
        return values
    raise OperatorHeaderError("operator headers use an unsupported container")


def _single_header(headers: Any, name: str) -> str:
    values = _header_values(headers, name)
    if len(values) != 1 or not isinstance(values[0], str):
        raise OperatorHeaderError(f"exactly one {name} header is required")
    value = values[0]
    if not value or value != value.strip() or any(
        ord(character) < 0x21 or ord(character) == 0x7F for character in value
    ):
        raise OperatorHeaderError(f"{name} is empty or non-canonical")
    return value


def parse_operator_headers(headers: Any) -> OperatorRequestHeaders:
    """Parse one strict signing header set and reject the legacy bearer header."""
    if _header_values(headers, LEGACY_OPERATOR_HEADER):
        raise OperatorHeaderError("legacy operator bearer authentication is refused")
    version = _single_header(headers, OPERATOR_HEADER_VERSION)
    if version != OPERATOR_AUTH_VERSION:
        raise OperatorHeaderError("unsupported operator authentication version")
    try:
        principal_id = validate_operator_principal(
            _single_header(headers, OPERATOR_HEADER_PRINCIPAL)
        )
        epoch, _epoch_text = _canonical_integer(
            _single_header(headers, OPERATOR_HEADER_EPOCH),
            "operator credential epoch",
            minimum=1,
        )
        timestamp, _timestamp_text = _canonical_integer(
            _single_header(headers, OPERATOR_HEADER_TIMESTAMP),
            "operator request timestamp",
            minimum=0,
        )
        request_id = _validate_request_id(
            _single_header(headers, OPERATOR_HEADER_REQUEST_ID)
        )
        supplied_signature = _single_header(headers, OPERATOR_HEADER_SIGNATURE)
        if not OPERATOR_SIGNATURE.fullmatch(supplied_signature):
            raise ValueError("operator signature is invalid")
    except ValueError as exc:
        raise OperatorHeaderError(str(exc)) from exc
    return OperatorRequestHeaders(
        principal_id=principal_id,
        credential_epoch=epoch,
        request_timestamp=timestamp,
        request_id=request_id,
        supplied_signature=supplied_signature,
        version=version,
    )


def authenticate_operator_request(
    token: str,
    headers: Any,
    method: str,
    target: str,
    body: bytes,
    *,
    expected_principal: str,
    expected_credential_epoch: int,
    max_clock_skew: float = OPERATOR_MAX_CLOCK_SKEW_SECONDS,
    now: float | None = None,
) -> OperatorRequestContext:
    """Return immutable verified authority or fail without exposing the reason."""
    try:
        parsed = parse_operator_headers(headers)
    except OperatorHeaderError as exc:
        raise OperatorAuthenticationError("invalid operator authentication") from exc
    if not verify_operator_request(
        token,
        parsed.principal_id,
        parsed.credential_epoch,
        parsed.request_timestamp,
        parsed.request_id,
        method,
        target,
        body,
        parsed.supplied_signature,
        expected_principal=expected_principal,
        expected_credential_epoch=expected_credential_epoch,
        max_clock_skew=max_clock_skew,
        now=now,
    ):
        raise OperatorAuthenticationError("invalid operator authentication")
    return OperatorRequestContext(
        principal_id=parsed.principal_id,
        credential_epoch=parsed.credential_epoch,
        request_timestamp=parsed.request_timestamp,
        request_id=parsed.request_id,
        supplied_signature=parsed.supplied_signature,
    )
