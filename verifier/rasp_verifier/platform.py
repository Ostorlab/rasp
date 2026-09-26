"""Platform attestation (Android Play Integrity, iOS App Attest), abstracted behind one interface.

Real Play Integrity verification decrypts and verifies a Google-signed token and needs a Google Cloud
project and the app's decryption/verification keys; App Attest needs Apple's anonymous attestation CA. Those
belong to a deployment, not this reference code, so the trust service takes a `PlatformAttestation`
implementation and ships two:

- `DisabledPlatformAttestation` (default): no platform verdict. The trust service then runs in the design's
  degraded mode — hardware Key Attestation plus the sealed report only, with the risk floor raised.
- `StubPlatformAttestation` (tests, demos): accepts a self-describing JSON token and checks the request
  hash and package. Never use it in production; it trusts the token's own claims.

A production deployment implements `PlatformAttestation.verify` against Google's / Apple's servers.
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
    # Android device-integrity tier (MEETS_STRONG_INTEGRITY -> STRONG, ...) or an iOS equivalent.
    verdict: str  # "STRONG" | "DEVICE" | "BASIC" | "NONE"
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
