"""Minimal authenticated request signing for agent traffic."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import threading
import time
from collections import OrderedDict


MAX_CLOCK_SKEW_SECONDS = 300
ENROLLMENT_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
PROFILE_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
AGENT_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


class ReplayGuard:
    """Reject reused signatures without letting one principal consume every marker.

    Every principal owns an independent, fail-closed replay partition.  The
    principal table is bounded as well; callers that authenticate a bounded
    identity population should set ``max_principals`` to that same bound.
    """

    def __init__(
        self,
        lifetime: float = MAX_CLOCK_SKEW_SECONDS * 2,
        max_entries: int = 100_000,
        max_principals: int = 1,
    ):
        self.lifetime = max(1.0, float(lifetime))
        self.max_entries = max(128, int(max_entries))
        self.max_principals = max(1, int(max_principals))
        self._seen: OrderedDict[str, OrderedDict[str, float]] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, markers: OrderedDict[str, float], current: float) -> None:
        while markers:
            first_key = next(iter(markers))
            if current - markers[first_key] <= self.lifetime:
                break
            markers.popitem(last=False)

    def accept(
        self,
        request_signature: str,
        now: float | None = None,
        *,
        principal: str = "default",
    ) -> bool:
        current = time.time() if now is None else float(now)
        identity = str(principal)
        with self._lock:
            markers = self._seen.get(identity)
            if markers is None:
                # Reclaim only partitions with no still-live replay evidence.
                # Never evict live markers merely to admit another principal.
                for existing in list(self._seen):
                    existing_markers = self._seen[existing]
                    self._prune(existing_markers, current)
                    if not existing_markers:
                        del self._seen[existing]
                if len(self._seen) >= self.max_principals:
                    return False
                markers = OrderedDict()
                self._seen[identity] = markers
            self._prune(markers, current)
            if request_signature in markers:
                return False
            if len(markers) >= self.max_entries:
                # Keep every still-live marker in this principal's partition.
                return False
            markers[request_signature] = current
            return True

    def clear(self, principal: str) -> None:
        """Forget only one lifecycle-invalidated identity partition."""
        with self._lock:
            self._seen.pop(str(principal), None)


class PrincipalRateLimiter:
    """Bounded per-principal token buckets with no cross-principal eviction."""

    def __init__(
        self,
        rate_per_second: float,
        burst: int,
        max_principals: int,
    ):
        if not math.isfinite(rate_per_second) or rate_per_second <= 0:
            raise ValueError("rate_per_second must be finite and positive")
        self.rate_per_second = float(rate_per_second)
        self.burst = max(1, int(burst))
        self.max_principals = max(1, int(max_principals))
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def consume(
        self,
        principal: str,
        now: float | None = None,
    ) -> tuple[bool, float]:
        """Consume one token and return ``(allowed, retry_after_seconds)``."""
        identity = str(principal)
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            previous = self._buckets.get(identity)
            if previous is None:
                if len(self._buckets) >= self.max_principals:
                    return False, 1.0 / self.rate_per_second
                tokens = float(self.burst)
                updated_at = current
            else:
                prior_tokens, prior_time = previous
                elapsed = max(0.0, current - prior_time)
                tokens = min(
                    float(self.burst),
                    prior_tokens + elapsed * self.rate_per_second,
                )
                updated_at = current
            if tokens < 1.0:
                self._buckets[identity] = (tokens, updated_at)
                return False, (1.0 - tokens) / self.rate_per_second
            self._buckets[identity] = (tokens - 1.0, updated_at)
            return True, 0.0


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def derive_agent_token(master_token: str, agent_id: str) -> str:
    """Derive a unique agent key without storing agent secrets server-side."""
    return hmac.new(
        master_token.encode(), f"sentinel-blue-agent-v1:{agent_id}".encode(), hashlib.sha256
    ).hexdigest()


def derive_enrollment_ticket(
    master_token: str, profile_fingerprint: str, agent_id: str
) -> str:
    """Derive the one-host enrollment authority for an exact release profile.

    Only this derived ticket is provisioned to the target host.  The NUL-delimited
    and domain-separated message prevents ambiguity with every other Sentinel Blue
    credential derivation.
    """
    if not isinstance(master_token, str) or not ENROLLMENT_TOKEN.fullmatch(
        master_token
    ):
        raise ValueError("enrollment master token is not a bounded URL-safe secret")
    if not isinstance(profile_fingerprint, str) or not PROFILE_FINGERPRINT.fullmatch(
        profile_fingerprint.casefold()
    ):
        raise ValueError("profile fingerprint is not a SHA-256 digest")
    if not isinstance(agent_id, str) or not AGENT_ID.fullmatch(agent_id):
        raise ValueError("agent_id contains unsupported characters")
    message = (
        b"sentinel-blue-enrollment-ticket-v1\x00"
        + profile_fingerprint.casefold().encode("ascii")
        + b"\x00"
        + agent_id.encode("ascii")
    )
    return hmac.new(master_token.encode("ascii"), message, hashlib.sha256).hexdigest()


def validate_operator_token(enrollment_token: str, operator_token: str) -> str:
    """Require operator authority to use independent secret material.

    Releases before 1.9.7 derived the operator credential from the shared
    enrollment secret.  Merely accepting that derived value from a separate
    file would preserve the same privilege-escalation path, so reject both the
    enrollment secret itself and the legacy derivation during migration.
    """
    if not isinstance(operator_token, str) or not ENROLLMENT_TOKEN.fullmatch(
        operator_token
    ):
        raise ValueError(
            "the operator token must be an independent 32-256 character "
            "URL-safe secret"
        )
    if not isinstance(enrollment_token, str):
        raise ValueError("the enrollment token must be a string")
    legacy_derived = hmac.new(
        enrollment_token.encode(), b"sentinel-blue-operator-v1", hashlib.sha256
    ).hexdigest()
    if hmac.compare_digest(operator_token, enrollment_token) or hmac.compare_digest(
        operator_token, legacy_derived
    ):
        raise ValueError(
            "the operator token is not independent of the enrollment token; "
            "rotate it before startup"
        )
    return operator_token


def _enrollment_keystream(master_token: str, request_signature: str, length: int) -> bytes:
    if not re.fullmatch(r"[a-f0-9]{64}", request_signature):
        raise ValueError("enrollment wrapping requires an authenticated request signature")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(
                master_token.encode(),
                b"sentinel-blue-enrollment-wrap-v1\x00"
                + request_signature.encode()
                + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def wrap_enrollment_token(
    master_token: str, request_signature: str, agent_token: str
) -> str:
    """Protect the new per-agent credential inside the authenticated response.

    The response HMAC provides authentication; this request-bound HMAC stream
    prevents a passive observer of optional lab HTTP traffic from recovering the
    credential. TLS is still required when telemetry confidentiality matters.
    """
    if not isinstance(agent_token, str) or not ENROLLMENT_TOKEN.fullmatch(agent_token):
        raise ValueError("agent token cannot be wrapped safely")
    plaintext = agent_token.encode("ascii")
    stream = _enrollment_keystream(master_token, request_signature, len(plaintext))
    return base64.urlsafe_b64encode(
        bytes(left ^ right for left, right in zip(plaintext, stream, strict=True))
    ).decode("ascii")


def unwrap_enrollment_token(
    master_token: str, request_signature: str, wrapped_token: str
) -> str:
    if not isinstance(wrapped_token, str) or not 40 <= len(wrapped_token) <= 344:
        raise ValueError("wrapped agent token is invalid")
    try:
        ciphertext = base64.b64decode(
            wrapped_token.encode("ascii"), altchars=b"-_", validate=True
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("wrapped agent token is invalid") from exc
    if not 32 <= len(ciphertext) <= 256:
        raise ValueError("wrapped agent token is invalid")
    stream = _enrollment_keystream(master_token, request_signature, len(ciphertext))
    try:
        token = bytes(
            left ^ right for left, right in zip(ciphertext, stream, strict=True)
        ).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("wrapped agent token is invalid") from exc
    if not ENROLLMENT_TOKEN.fullmatch(token):
        raise ValueError("wrapped agent token is invalid")
    return token


def signature(token: str, timestamp: str, method: str, path: str, body: bytes) -> str:
    canonical = "\n".join((timestamp, method.upper(), path, body_digest(body)))
    return hmac.new(token.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def response_signature(
    token: str,
    timestamp: str,
    status: int,
    path: str,
    request_signature: str,
    body: bytes,
) -> str:
    """Bind a response to its status and the exact authenticated request.

    Signing only the response body permits an on-path peer to turn a signed
    rejection into an apparent success by changing the unsigned HTTP status.
    Binding the originating request signature also prevents a withheld response
    from being substituted for a later poll to the same endpoint.
    """
    canonical = "\n".join(
        (
            "sentinel-blue-response-v2",
            timestamp,
            str(int(status)),
            path,
            request_signature,
            body_digest(body),
        )
    )
    return hmac.new(token.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def verify(
    token: str,
    timestamp: str,
    method: str,
    path: str,
    body: bytes,
    supplied_signature: str,
    now: float | None = None,
) -> bool:
    try:
        request_time = float(timestamp)
        current = float(time.time() if now is None else now)
    except (TypeError, ValueError):
        return False
    if (
        not math.isfinite(request_time)
        or not math.isfinite(current)
        or abs(current - request_time) > MAX_CLOCK_SKEW_SECONDS
    ):
        return False
    expected = signature(token, timestamp, method, path, body)
    return hmac.compare_digest(expected, supplied_signature)


def verify_response(
    token: str,
    timestamp: str,
    status: int,
    path: str,
    request_signature: str,
    body: bytes,
    supplied_signature: str,
    now: float | None = None,
) -> bool:
    try:
        request_time = float(timestamp)
        response_status = int(status)
        current = float(time.time() if now is None else now)
    except (TypeError, ValueError):
        return False
    if (
        not math.isfinite(request_time)
        or not math.isfinite(current)
        or abs(current - request_time) > MAX_CLOCK_SKEW_SECONDS
        or not 100 <= response_status <= 599
        or len(request_signature) != 64
    ):
        return False
    expected = response_signature(
        token,
        timestamp,
        response_status,
        path,
        request_signature,
        body,
    )
    return hmac.compare_digest(expected, supplied_signature)
