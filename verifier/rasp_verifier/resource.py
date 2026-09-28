"""Helpers for a resource server (the customer's backend) that consumes trust-service tokens.

The backend never verifies the device's report itself. It verifies the short-lived integrity token the
trust service signed (via the published JWKS), checks that the request is bound to the install key the token
was issued to (a DPoP-style proof of possession), and maps the token's risk to allow / step-up / deny for
that endpoint. A stolen token is useless without the install key, and a proof made for one request cannot be
moved to another.

Wire format (headers on every protected request):
    X-Integrity-Token    the trust-service JWT
    X-Integrity-Key      the install public key, SubjectPublicKeyInfo DER, base64
    X-Integrity-Sig      ES256 proof (raw R||S, base64url) over the canonical request string
    X-Integrity-Ts       device time, ms, when the proof was made
    X-Integrity-Counter  a per-install monotonic counter
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field

from . import jose
from rasp_verifier import storage
from .policy import RISK_ORDER

MAX_PROOF_SKEW_SECONDS = 300


class ResourceError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def canonical_request(method: str, path: str, body: bytes, ts_ms: int, counter: int) -> bytes:
    """The exact string the install key signs for a request. Body is bound by its SHA-256."""
    body_hash = jose.b64u_encode(hashlib.sha256(body).digest())
    return f"rasp-req-1\n{method.upper()}\n{path}\n{body_hash}\n{ts_ms}\n{counter}".encode()


@dataclass
class VerifiedRequest:
    claims: dict
    install_id: str
    risk: str
    threats: list[str]
    counter: int


def verify_request(
    *,
    token: str,
    install_key_der_b64: str,
    signature_b64: str,
    ts_ms: int,
    counter: int,
    method: str,
    path: str,
    body: bytes,
    jwks_keys: list[dict],
    now: float | None = None,
    last_counter: int | None = None,
    replay_store: storage.Store | None = None,
) -> VerifiedRequest:
    """Verifies the token, that the request is bound to the token's install key, and freshness.

    `last_counter`, when given, is the highest counter already seen for this install; the proof must exceed
    it, which stops a captured proof being replayed. The caller persists the returned counter.
    """
    try:
        claims = jose.decode_jwt(token, jwks_keys, now=now)
    except jose.JoseError as error:
        raise ResourceError(error.reason) from error
    if replay_store is not None and (claims.get("tenant") != replay_store.scope.tenant_id or
                                     claims.get("appId") != replay_store.scope.app_id):
        raise ResourceError("wrong_scope")
    if type(counter) is not int or counter <= 0:
        raise ResourceError("bad_counter")
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        raise ResourceError("no_cnf")
    jkt = cnf.get("jkt")
    if not isinstance(jkt, str) or jkt == "":
        raise ResourceError("no_cnf", "token has no bound-key confirmation")

    try:
        public_key = jose.load_public_key_der(base64.b64decode(install_key_der_b64, validate=True))
    except (jose.JoseError, ValueError) as error:
        raise ResourceError("bad_key") from error
    if jose.public_key_thumbprint(public_key) != jkt:
        raise ResourceError("key_mismatch", "presented key is not the token's bound key")

    if not isinstance(claims.get("sub"), str) or claims["sub"] == "" or claims.get("risk") not in RISK_ORDER:
        raise ResourceError("bad_claim")
    if not isinstance(claims.get("signals"), list) or any(not isinstance(item, str) for item in claims["signals"]):
        raise ResourceError("bad_claim")
    now = time.time() if now is None else now
    if abs(now - ts_ms / 1000) > MAX_PROOF_SKEW_SECONDS:
        raise ResourceError("stale_proof", f"ts {ts_ms}")
    if last_counter is not None and counter <= last_counter:
        raise ResourceError("replayed_proof", f"counter {counter} <= {last_counter}")

    message = canonical_request(method, path, body, ts_ms, counter)
    try:
        jose.verify_proof(public_key, message, signature_b64)
    except jose.JoseError as e:
        raise ResourceError("bad_proof", e.reason) from e

    if replay_store is not None and replay_store.advance_counter("request:" + jkt, counter) is False:
        raise ResourceError("replayed_proof")

    return VerifiedRequest(
        claims=claims,
        install_id=str(claims.get("sub", "")),
        risk=str(claims.get("risk", "high")),
        threats=list(claims.get("signals", [])),
        counter=counter,
    )


@dataclass
class Decision:
    action: str  # "allow" | "step_up" | "deny"
    reasons: list[str] = field(default_factory=list)


def decide(risk: str, threats: list[str] | None = None, *, deny_at: str = "critical", step_up_at: str = "medium") -> Decision:
    """Maps a token's risk to an action for one endpoint. Sensitive endpoints pass a lower `deny_at`."""
    level = RISK_ORDER.index(risk) if risk in RISK_ORDER else RISK_ORDER.index("high")
    reasons = [f"risk:{risk}"] + [f"threat:{t}" for t in (threats or [])]
    if level >= RISK_ORDER.index(deny_at):
        return Decision("deny", reasons)
    if level >= RISK_ORDER.index(step_up_at):
        return Decision("step_up", reasons)
    return Decision("allow", [f"risk:{risk}"])
