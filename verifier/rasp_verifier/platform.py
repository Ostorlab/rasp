"""Platform attestation (Android Play Integrity, iOS App Attest), abstracted behind one interface.

Production adapters live in `play_integrity` (Google OAuth decode API) and `app_attest`
(Apple certificate/authenticator validation plus stateful assertions). Configure their
application identity and deployment credentials explicitly. App Attest uses separate
bind/token routes because its key lifecycle cannot be represented by this stateless interface.

DisabledPlatformAttestation preserves degraded demo mode; StubPlatformAttestation is
strictly for tests/demos and must never be enabled in a production deployment.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass


class PlatformAttestationError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class PlatformVerdict:
    # Android device-integrity tier or distinct iOS app/key origin evidence.
    verdict: str  # "STRONG" | "DEVICE" | "BASIC" | "NONE" | "APP_ATTEST"
    app_recognized: bool
    raw: dict


class PlatformAttestation:
    """Interface. `available` says whether a token is expected at all."""

    available: bool = True

    def verify(self, token: str, *, request_hash: bytes, package_name: str) -> PlatformVerdict:
        raise NotImplementedError


class DisabledPlatformAttestation(PlatformAttestation):
    available = False

    def verify(self, token: str, *, request_hash: bytes, package_name: str) -> PlatformVerdict:
        raise PlatformAttestationError("disabled", "no platform attestation configured")


class StubPlatformAttestation(PlatformAttestation):
    """Test/demo only. The token is JSON: {"verdict","package","requestHash"(b64),"appRecognized"?}."""

    available = True

    def verify(self, token: str, *, request_hash: bytes, package_name: str) -> PlatformVerdict:
        try:
            claims = json.loads(token)
        except ValueError as e:
            raise PlatformAttestationError("bad_token", str(e)) from e
        if claims.get("package") != package_name:
            raise PlatformAttestationError("wrong_package", str(claims.get("package")))
        presented = base64.b64decode(claims.get("requestHash", ""))
        if not presented or presented != request_hash:
            raise PlatformAttestationError("request_hash_mismatch")
        return PlatformVerdict(
            verdict=str(claims.get("verdict", "NONE")),
            app_recognized=bool(claims.get("appRecognized", True)),
            raw=claims,
        )


def request_hash(nonce_b64: str) -> bytes:
    """The value the client must bind the platform attestation to: SHA-256 of the challenge nonce.

    The Android client passes this as Play Integrity's `requestHash`; iOS passes it as App Attest's
    `clientDataHash`. Binding to the trust service's single-use nonce stops a platform token minted for one
    session being replayed into another.
    """
    return hashlib.sha256(nonce_b64.encode()).digest()
