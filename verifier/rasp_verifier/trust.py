"""The trust service core: issues single-use challenges, binds installs with hardware Key Attestation, and
mints short-lived integrity tokens from a sealed RASP report, hardware attestation and a platform verdict.

This is the component whose verdict a resource server acts on. It holds the token signing key and makes the
authoritative trust decision; the device only reports. HTTP is a thin layer over this class (`trust_server`),
so the flow is testable without sockets.

Flow:
    challenge(bind)  -> nonce
    bind             -> verify Key Attestation for that nonce; store the install's attested public key
    challenge(token) -> nonce
    token            -> verify proof of possession, the sealed report (build-key MAC) and the platform
                        verdict for that nonce; score risk; sign a JWT bound to the install key (cnf.jkt)
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import uuid

from . import jose
from rasp_verifier import storage
from rasp_verifier import app_attest
from rasp_verifier import registry
from rasp_verifier import durable_registry
from .attestation import AttestationError, verify_key_attestation
from .platform import DisabledPlatformAttestation, PlatformAttestation, PlatformAttestationError, request_hash
from .policy import TokenPolicy, assess_risk, token_ttl
from .registry import BuildRegistry, Install, InstallRegistry, RegistryError
from .report import ReportError, verify_sealed_report

ISSUER = "rasp-trust"
CHALLENGE_TTL_SECONDS = 120


class TrustError(Exception):
    """A challenge, bind or token request was refused. `reason` is a stable machine-readable code."""

    def __init__(self, reason: str, detail: str = "", status: int = 403):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
        self.status = status


def token_proof_message(nonce: str, report_mac: str, session_jkt: str) -> bytes:
    """What the user-auth install key signs at token issuance.

    It binds the challenge, the sealed report, and the ephemeral session key the token will be bound to. So
    one user authentication (a biometric prompt showing the action) authorizes a short-lived token whose
    per-request proofs the session key then makes silently, with no prompt per request.
    """
    return f"rasp-token-1\n{nonce}\n{report_mac}\n{session_jkt}".encode()


class TrustService:
    def __init__(
        self,
        *,
        signing_key: jose.SigningKey,
        package_name: str,
        signing_cert_sha256: list[str],
        builds: registry.BuildRepository,
        installs: registry.InstallRepository | None = None,
        platform_attestation: PlatformAttestation | None = None,
        policy: TokenPolicy | None = None,
        revocations=None,
        trusted_roots=None,
        state: storage.Store | None = None,
        apple_verifier: app_attest.AppAttestVerifier | None = None,
    ):
        self.app_attest = apple_verifier
        self.signing_key = signing_key
        self.package_name = package_name
        self.signing_cert_sha256 = signing_cert_sha256
        self.state = storage.MemoryStore() if state is None else state
        self.builds = builds
        self.installs = installs if installs is not None else durable_registry.InstallRegistry(self.state)
        if self.builds.scope != self.state.scope or self.installs.scope != self.state.scope:
            raise ValueError("all repositories must share the trust application scope")
        if apple_verifier is not None and apple_verifier.app_id.endswith("." + package_name) is False:
            raise ValueError("App Attest bundle ID must match trust application")
        self.platform = platform_attestation or DisabledPlatformAttestation()
        self.policy = policy or TokenPolicy()
        self.revocations = revocations
        self.trusted_roots = trusted_roots

    # --- JWKS -----------------------------------------------------------------------------------------------

    def jwks(self) -> dict:
        return {"keys": [self.signing_key.public_jwk()]}

    # --- challenges -----------------------------------------------------------------------------------------

    def challenge(self, install_id: str, purpose: str) -> dict:
        if purpose not in ("bind", "token", "ios-bind", "ios-token"):
            raise TrustError("bad_purpose", purpose, status=400)
        if not install_id:
            raise TrustError("no_install", status=400)
        nonce = base64.b64encode(secrets.token_bytes(32)).decode()
        self.state.put_challenge(nonce, purpose, install_id, time.time() + CHALLENGE_TTL_SECONDS)
        return {"nonce": nonce, "expiresIn": CHALLENGE_TTL_SECONDS}

    def _consume(self, nonce: str, purpose: str, install_id: str) -> bool:
        return self.state.consume_challenge(nonce, purpose, install_id, time.time())

    def _current_revocations(self):
        if self.revocations is None:
            return None
        current = self.revocations.current()
        if current is None:  # fail closed: without a fresh list, revoked keyboxes would be accepted
            raise TrustError("revocation_unavailable", status=503)
        return current

    # --- bind -----------------------------------------------------------------------------------------------

    def bind(self, body: dict) -> dict:
        install_id = str(body.get("installId", ""))
        nonce = str(body.get("nonce", ""))
        if not self._consume(nonce, "bind", install_id):
            raise TrustError("bad_challenge", "unknown, used or expired", status=400)
        revocations = self._current_revocations()
        try:
            result = verify_key_attestation(
                body.get("certificateChain", []),
                base64.b64decode(nonce),
                self.package_name,
                self.signing_cert_sha256,
                require_hardware=self.policy.require_hardware,
                require_user_auth=self.policy.require_user_auth,
                trusted_roots=self.trusted_roots,
                revocations=revocations,
            )
        except AttestationError as e:
            raise TrustError("attestation_failed", f"{e.reason}: {e}", status=403) from e

        if base64.b64decode(body.get("publicKey", "")) != result.public_key_der:
            raise TrustError("key_mismatch", "presented key is not the attested key", status=403)

        # A platform token at bind time is optional; when present it must match this nonce.
        if body.get("playIntegrityToken") and self.platform.available:
            try:
                self.platform.verify(
                    body["playIntegrityToken"], request_hash=request_hash(nonce), package_name=self.package_name
                )
            except PlatformAttestationError as e:
                raise TrustError("platform_failed", e.reason, status=403) from e

        install = Install(
            install_id=install_id,
            public_key_der=result.public_key_der,
            thumbprint=jose.public_key_thumbprint(jose.load_public_key_der(result.public_key_der)),
            security_level=result.security_level,
            verified_boot_state=result.verified_boot_state,
            device_locked=result.device_locked,
            os_patch_level=result.os_patch_level,
            user_auth_required=result.user_auth_required,
            attestation_warnings=result.warnings,
        )
        try:
            self.installs.bind(install)
        except RegistryError as error:
            raise TrustError(error.reason, status=409) from error
        return {
            "bound": True,
            "installId": install_id,
            "securityLevel": result.security_level,
            "trustedRoot": result.trusted_root,
            "userAuthRequired": result.user_auth_required,
            "verifiedBootState": result.verified_boot_state,
            "warnings": result.warnings,
        }

    def bind_ios(self, body: dict) -> dict:
        if self.app_attest is None:
            raise TrustError("app_attest_unavailable", status=503)
        install_id, nonce = str(body.get("installId", "")), str(body.get("nonce", ""))
        if self._consume(nonce, "ios-bind", install_id) is False:
            raise TrustError("bad_challenge", status=400)
        try:
            result = self.app_attest.verify_attestation(body.get("attestationObject", ""),
                                                       body.get("keyId", ""), request_hash(nonce))
            self.installs.bind(Install(
                install_id=install_id, public_key_der=result.public_key_der,
                thumbprint=jose.public_key_thumbprint(jose.load_public_key_der(result.public_key_der)),
                security_level="app_attest", verified_boot_state=None, device_locked=None,
                os_patch_level=None, user_auth_required=False, platform="ios", app_attest_key_id=result.key_id))
        except PlatformAttestationError as error:
            raise TrustError("attestation_failed", error.reason) from error
        except RegistryError as error:
            raise TrustError(error.reason, status=409) from error
        return {"bound": True, "installId": install_id, "securityLevel": "app_attest", "userAuthRequired": False}

    def token_ios(self, body: dict) -> dict:
        return self._token(body, ios=True)

    # --- token ----------------------------------------------------------------------------------------------

    def token(self, body: dict) -> dict:
        return self._token(body, ios=False)

    def _token(self, body: dict, *, ios: bool) -> dict:
        install_id = str(body.get("installId", ""))
        nonce = str(body.get("nonce", ""))
        if not self._consume(nonce, "ios-token" if ios is True else "token", install_id):
            raise TrustError("bad_challenge", "unknown, used or expired", status=400)
        try:
            install = self.installs.get(install_id)
        except RegistryError as e:
            raise TrustError("unknown_install", str(e), status=403) from e

        if install.platform != ("ios" if ios is True else "android"):
            raise TrustError("wrong_platform")
        envelope = body.get("sealedReport")
        if not isinstance(envelope, dict):
            raise TrustError("bad_report", status=400)
        mac = envelope.get("mac")
        if not isinstance(envelope.get("report"), str) or not isinstance(mac, str):
            raise TrustError("bad_report", "sealedReport.report and .mac are required", status=400)

        # The ephemeral session key the token will be bound to (cnf). The install key authorizes it.
        try:
            session_key = jose.load_public_key_der(base64.b64decode(str(body.get("sessionPublicKey", ""))))
        except (jose.JoseError, ValueError) as e:
            raise TrustError("bad_session_key", str(e), status=400) from e
        session_jkt = jose.public_key_thumbprint(session_key)

        if ios is True:
            if self.app_attest is None:
                raise TrustError("app_attest_unavailable", status=503)
            if body.get("keyId") != install.app_attest_key_id:
                raise TrustError("key_mismatch")
            try:
                self.app_attest.verify_assertion(body.get("assertion", ""), install.public_key_der,
                    install.app_attest_key_id, hashlib.sha256(token_proof_message(nonce, mac, session_jkt)).digest(), self.state)
            except PlatformAttestationError as error:
                raise TrustError("platform_failed", error.reason) from error
        else:
            install_key = jose.load_public_key_der(install.public_key_der)
            try:
                jose.verify_proof(install_key, token_proof_message(nonce, mac, session_jkt), str(body.get("proof", "")))
            except jose.JoseError as error:
                raise TrustError("bad_proof", error.reason, status=403) from error

        # Select the build key by the buildId inside the report (unverified peek), then authenticate the
        # report with that key's MAC.
        try:
            build_id = str(json.loads(envelope["report"])["buildId"])
        except (ValueError, KeyError, TypeError) as e:
            raise TrustError("bad_report", str(e), status=400) from e
        try:
            build = self.builds.get(build_id)
        except RegistryError as e:
            raise TrustError(e.reason, str(e), status=403) from e
        if (build.package_name != self.package_name or
                set(build.signing_cert_sha256) != set(self.signing_cert_sha256)):
            raise TrustError("wrong_build_identity", status=403)
        try:
            # Integrity-derived sealing (design §8): a build registered with a non-empty integrity root is
            # verified with HMAC(build_key, root), which the device reproduces by hashing its own `.so`
            # regions (see integrity.c / codehash.so_integrity_root). A tampered binary derives a different
            # root and is refused. `or None` keeps the raw-key path deliberate for builds with no root (dev
            # builds, and any build registered without a `.so`).
            report = verify_sealed_report(
                envelope, build_key=build.build_key, expected_nonce=nonce,
                integrity_root=build.integrity_root or None,
            )
        except ReportError as e:
            raise TrustError("bad_report", f"{e.reason}: {e}", status=403) from e

        # Platform attestation (Play Integrity / App Attest) for this nonce.
        platform_verdict = "APP_ATTEST" if ios is True else None
        platform_available = ios is True or self.platform.available
        if platform_available and ios is False:
            token_str = body.get("playIntegrityToken")
            if not token_str:
                raise TrustError("platform_required", "platform attestation is configured", status=403)
            try:
                verdict = self.platform.verify(
                    token_str, request_hash=request_hash(nonce), package_name=self.package_name
                )
            except PlatformAttestationError as e:
                raise TrustError("platform_failed", e.reason, status=403) from e
            platform_verdict = verdict.verdict if verdict.app_recognized else "NONE"

        assessment = assess_risk(
            report_threats=report.threats,
            attestation_security_level=install.security_level,
            device_locked=install.device_locked,
            verified_boot_state=install.verified_boot_state,
            platform_verdict=platform_verdict,
            platform_available=platform_available,
            policy=self.policy,
        )
        if assessment.risk in self.policy.deny_token_on:
            raise TrustError("token_denied", f"risk {assessment.risk}", status=403)

        now = int(time.time())
        ttl = token_ttl(assessment.risk)
        claims = {
            "iss": ISSUER,
            "aud": "rasp-resource",
            "tenant": self.state.scope.tenant_id,
            "appId": self.state.scope.app_id,
            "sub": install_id,
            "app": self.package_name,
            "build": build_id,
            "risk": assessment.risk,
            "signals": assessment.threat_summary,
            "uauth": install.user_auth_required,
            "sec": install.security_level,
            # The token is bound to the ephemeral session key; the install key that authorized it (and its
            # per-use user-auth property) is reflected in `uauth`.
            "cnf": {"jkt": session_jkt},
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,
        }
        return {
            "token": self.signing_key.sign_jwt(claims),
            "tokenType": "DPoP",
            "expiresIn": ttl,
            "risk": assessment.risk,
            "reasons": assessment.reasons,
        }
