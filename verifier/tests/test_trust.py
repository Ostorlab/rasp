"""End-to-end tests for the trust service: challenge -> bind -> token, and the ways it refuses."""

import base64
import hashlib
import hmac
import typing
import unittest

from rasp_verifier import jose
from rasp_verifier.platform import DisabledPlatformAttestation, StubPlatformAttestation
from rasp_verifier.policy import TokenPolicy
from rasp_verifier.registry import Build, BuildRegistry, InstallRegistry
from rasp_verifier.trust import TrustError, TrustService, token_proof_message

from .helpers import (
    BUILD_ID,
    BUILD_KEY,
    APP_CERT_SHA256,
    PACKAGE,
    Chain,
    raw_es256,
    seal_report,
    session_keypair,
    stub_play_integrity,
)


def make_service(*, platform=None, require_hardware=True, require_user_auth=True, integrity_root=""):
    builds = BuildRegistry([Build(BUILD_ID, BUILD_KEY, PACKAGE, [APP_CERT_SHA256], integrity_root=integrity_root)])
    return TrustService(
        signing_key=jose.SigningKey.generate(),
        package_name=PACKAGE,
        signing_cert_sha256=[APP_CERT_SHA256],
        builds=builds,
        installs=InstallRegistry(),
        platform_attestation=platform or StubPlatformAttestation(),
        policy=TokenPolicy(require_hardware=require_hardware, require_user_auth=require_user_auth),
        revocations=None,
    )


class TrustFlow(unittest.TestCase):
    def testTrustService_whenResolvingConstructorAnnotations_resolvesSigningKey(self) -> None:
        annotations = typing.get_type_hints(TrustService.__init__)

        self.assertIs(annotations["signing_key"], jose.SigningKey)

    def setUp(self):
        self.trust = make_service()
        self.trust.trusted_roots = None  # set per-bind below

    def _bind(self, install_id="install-1", **kd):
        nonce = self.trust.challenge(install_id, "bind")["nonce"]
        chain = Chain(base64.b64decode(nonce), user_auth=kd.pop("user_auth", True), **kd)
        self.trust.trusted_roots = [chain.root]
        result = self.trust.bind({
            "installId": install_id,
            "nonce": nonce,
            "publicKey": base64.b64encode(chain.public_key_der()).decode(),
            "certificateChain": chain.b64(),
            "playIntegrityToken": stub_play_integrity(nonce),
        })
        return chain, result

    def _token(self, chain, install_id="install-1", signals=(), verdict="STRONG", seal_key=None, **overrides):
        nonce = self.trust.challenge(install_id, "token")["nonce"]
        sealed = overrides.pop("sealed", None)
        if sealed is None:
            sealed = seal_report(nonce, signals, build_key=seal_key) if seal_key is not None else seal_report(nonce, signals)
        session_key, session_b64 = session_keypair()
        self.last_session_key = session_key
        session_jkt = jose.public_key_thumbprint(session_key.public_key())
        proof = overrides.pop("proof", None)
        if proof is None:
            proof = raw_es256(chain.device_key, token_proof_message(nonce, sealed["mac"], session_jkt))
        body = {
            "installId": install_id,
            "nonce": nonce,
            "proof": proof,
            "sessionPublicKey": session_b64,
            "sealedReport": sealed,
            "playIntegrityToken": stub_play_integrity(nonce, verdict=verdict),
        }
        body.update(overrides)
        return self.trust.token(body)

    def claims(self, token):
        return jose.decode_jwt(token, self.trust.jwks()["keys"])

    def test_clean_device_gets_a_low_risk_token(self):
        chain, result = self._bind()
        self.assertTrue(result["bound"])
        self.assertTrue(result["userAuthRequired"])
        issued = self._token(chain)
        self.assertEqual(issued["risk"], "none")
        claims = self.claims(issued["token"])
        self.assertEqual(claims["app"], PACKAGE)
        self.assertEqual(claims["build"], BUILD_ID)
        # The token is bound to the ephemeral session key, not the install key directly.
        self.assertEqual(claims["cnf"]["jkt"], jose.public_key_thumbprint(self.last_session_key.public_key()))
        self.assertTrue(claims["uauth"])

    def test_hooking_in_the_report_is_critical(self):
        chain, _ = self._bind()
        issued = self._token(chain, signals=[("hooking", 90, "native.maps", "frida-agent.so")])
        self.assertEqual(issued["risk"], "critical")
        self.assertIn("hooking", self.claims(issued["token"])["signals"])

    def test_root_is_medium(self):
        chain, _ = self._bind()
        issued = self._token(chain, signals=[("root", 90, "native.su_binary", "/system/xbin/su")])
        self.assertEqual(issued["risk"], "medium")

    def test_degraded_when_no_platform_attestation(self):
        self.trust = make_service(platform=DisabledPlatformAttestation())
        chain, _ = self._bind()
        nonce = self.trust.challenge("install-1", "token")["nonce"]
        sealed = seal_report(nonce)
        session_key, session_b64 = session_keypair()
        jkt = jose.public_key_thumbprint(session_key.public_key())
        proof = raw_es256(chain.device_key, token_proof_message(nonce, sealed["mac"], jkt))
        issued = self.trust.token({"installId": "install-1", "nonce": nonce, "proof": proof,
                                   "sessionPublicKey": session_b64, "sealedReport": sealed})
        self.assertEqual(issued["risk"], "medium")  # clean report, but no platform proof -> floor raised

    def test_weak_play_integrity_verdict_is_high(self):
        chain, _ = self._bind()
        issued = self._token(chain, verdict="BASIC")
        self.assertEqual(issued["risk"], "high")

    def test_repackaged_app_wrong_build_key_is_refused(self):
        chain, _ = self._bind()
        # A repackaged build cannot know the genuine per-build MAC key, so its report fails the MAC. The
        # sealed report's own nonce is replaced with the token nonce inside _token via a fresh seal below.
        nonce = self.trust.challenge("install-1", "token")["nonce"]
        forged = seal_report(nonce, build_key=b"\x00" * 32)
        session_key, session_b64 = session_keypair()
        jkt = jose.public_key_thumbprint(session_key.public_key())
        proof = raw_es256(chain.device_key, token_proof_message(nonce, forged["mac"], jkt))
        with self.assertRaises(TrustError) as cm:
            self.trust.token({"installId": "install-1", "nonce": nonce, "proof": proof, "sessionPublicKey": session_b64,
                              "sealedReport": forged, "playIntegrityToken": stub_play_integrity(nonce)})
        self.assertEqual(cm.exception.reason, "bad_report")

    def test_forged_proof_is_refused(self):
        chain, _ = self._bind()
        other = Chain(b"x" * 32)
        with self.assertRaises(TrustError) as cm:
            self._token(chain, proof=raw_es256(other.device_key, b"rasp-token-1\nx\ny\nz"))
        self.assertEqual(cm.exception.reason, "bad_proof")

    def test_report_bound_to_a_different_nonce_is_refused(self):
        chain, _ = self._bind()
        stale = seal_report("some-other-nonce")
        with self.assertRaises(TrustError) as cm:
            self._token(chain, sealed=stale)
        self.assertEqual(cm.exception.reason, "bad_report")

    def test_challenge_is_single_use(self):
        chain, _ = self._bind()
        nonce = self.trust.challenge("install-1", "token")["nonce"]
        sealed = seal_report(nonce)
        session_key, session_b64 = session_keypair()
        jkt = jose.public_key_thumbprint(session_key.public_key())
        proof = raw_es256(chain.device_key, token_proof_message(nonce, sealed["mac"], jkt))
        body = {"installId": "install-1", "nonce": nonce, "proof": proof, "sessionPublicKey": session_b64,
                "sealedReport": sealed, "playIntegrityToken": stub_play_integrity(nonce)}
        self.trust.token(body)
        with self.assertRaises(TrustError) as cm:
            self.trust.token(body)
        self.assertEqual(cm.exception.reason, "bad_challenge")

    def test_token_without_binding_is_refused(self):
        # Different, never-bound install id.
        chain = Chain(b"z" * 32)
        with self.assertRaises(TrustError) as cm:
            self._token(chain, install_id="never-bound")
        self.assertEqual(cm.exception.reason, "unknown_install")

    def test_unknown_build_is_refused(self):
        chain, _ = self._bind()
        nonce = self.trust.challenge("install-1", "token")["nonce"]
        sealed = seal_report(nonce, build_id="not-registered")
        session_key, session_b64 = session_keypair()
        jkt = jose.public_key_thumbprint(session_key.public_key())
        proof = raw_es256(chain.device_key, token_proof_message(nonce, sealed["mac"], jkt))
        with self.assertRaises(TrustError) as cm:
            self.trust.token({"installId": "install-1", "nonce": nonce, "proof": proof, "sessionPublicKey": session_b64,
                              "sealedReport": sealed, "playIntegrityToken": stub_play_integrity(nonce)})
        self.assertEqual(cm.exception.reason, "unknown_build")

    def test_integrity_derived_sealing_is_accepted(self):
        # A build registered with an integrity root: the device seals with HMAC(build_key, root), and the
        # trust service verifies with the same derived key (design §8, end-to-end through the token route).
        root_hex = "5a" * 32
        self.trust = make_service(integrity_root=root_hex)
        self.trust.trusted_roots = None
        chain, _ = self._bind()
        derived = hmac.new(BUILD_KEY, bytes.fromhex(root_hex), hashlib.sha256).digest()
        issued = self._token(chain, seal_key=derived)
        self.assertEqual(issued["risk"], "none")
        self.assertEqual(self.claims(issued["token"])["build"], BUILD_ID)

    def test_integrity_registered_but_raw_key_seal_is_refused(self):
        # Same build, but a report sealed with the RAW key (a tampered/legacy device) must be refused.
        self.trust = make_service(integrity_root="5a" * 32)
        self.trust.trusted_roots = None
        chain, _ = self._bind()
        with self.assertRaises(TrustError) as cm:
            self._token(chain)  # seal_key=None -> raw BUILD_KEY
        self.assertEqual(cm.exception.reason, "bad_report")


if __name__ == "__main__":
    unittest.main()
