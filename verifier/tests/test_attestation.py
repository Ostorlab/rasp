import datetime as dt
import unittest

from rasp_verifier.attestation import AttestationError, load_google_roots, verify_key_attestation
from tests.helpers import APP_CERT_SHA256, PACKAGE, Chain

CHALLENGE = b"c" * 32


class VerifyKeyAttestationTest(unittest.TestCase):
    def verify(self, chain: Chain, challenge: bytes = CHALLENGE, **kwargs):
        kwargs.setdefault("trusted_roots", [chain.root])
        return verify_key_attestation(chain.b64(), challenge, PACKAGE, [APP_CERT_SHA256], **kwargs)

    def assert_reason(self, reason: str, fn):
        with self.assertRaises(AttestationError) as ctx:
            fn()
        self.assertEqual(reason, ctx.exception.reason)

    def test_valid_hardware_attestation(self):
        chain = Chain(CHALLENGE)
        result = self.verify(chain)
        self.assertEqual("tee", result.security_level)
        self.assertTrue(result.trusted_root)
        self.assertEqual("verified", result.verified_boot_state)
        self.assertTrue(result.device_locked)
        self.assertEqual(202609, result.os_patch_level)
        self.assertEqual(chain.public_key_der(), result.public_key_der)

    def test_strongbox_level(self):
        self.assertEqual("strongbox", self.verify(Chain(CHALLENGE, security_level=2)).security_level)

    def test_wrong_challenge(self):
        self.assert_reason("challenge_mismatch", lambda: self.verify(Chain(CHALLENGE), challenge=b"x" * 32))

    def test_relayed_attestation_from_another_app_is_rejected(self):
        # The attestation relay attack: a genuine chain obtained for a different app.
        self.assert_reason("wrong_package", lambda: self.verify(Chain(CHALLENGE, package="com.attacker.app")))

    def test_repackaged_app_is_rejected(self):
        self.assert_reason("wrong_signer", lambda: self.verify(Chain(CHALLENGE, app_cert_sha256="ab" * 32)))

    def test_untrusted_root(self):
        chain = Chain(CHALLENGE)
        self.assert_reason("untrusted_root", lambda: self.verify(chain, trusted_roots=load_google_roots()))

    def test_broken_chain(self):
        chain, other = Chain(CHALLENGE), Chain(CHALLENGE)
        chain.intermediate = other.intermediate
        self.assert_reason("bad_chain", lambda: self.verify(chain))

    def test_revoked_intermediate(self):
        chain = Chain(CHALLENGE, intermediate_serial=0xBEEF)
        self.assert_reason("revoked", lambda: self.verify(chain, revocations={"beef": "REVOKED"}))

    def test_expired_intermediate(self):
        chain = Chain(CHALLENGE)
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=400)
        self.assert_reason("expired_chain", lambda: self.verify(chain, now=later))

    def test_software_key_rejected_when_hardware_required(self):
        self.assert_reason("software_key", lambda: self.verify(Chain(CHALLENGE, security_level=0)))

    def test_unlocked_bootloader_rejected(self):
        self.assert_reason("unlocked_device", lambda: self.verify(Chain(CHALLENGE, locked=False, boot_state=2)))

    def test_software_allowed_with_warnings_for_emulators(self):
        chain = Chain(CHALLENGE, security_level=0)
        result = self.verify(chain, trusted_roots=[], require_hardware=False)
        self.assertEqual(["untrusted_root", "software_key"], result.warnings)
        # App identity is still enforced in lenient mode.
        self.assert_reason("wrong_package", lambda: self.verify(
            Chain(CHALLENGE, package="com.attacker.app"), trusted_roots=[], require_hardware=False))

    def test_certificate_signed_by_the_attested_key_is_rejected(self):
        # Regression for the review finding: an unlocked device's genuine chain plus a forged certificate below the
        # leaf, signed by the attested app key, claiming a locked and verified device.
        chain = Chain(CHALLENGE, locked=False, boot_state=2)
        forged, _ = chain.forge_below_leaf(CHALLENGE)
        with self.assertRaises(AttestationError) as ctx:
            verify_key_attestation(chain.b64(extra_below_leaf=forged), CHALLENGE, PACKAGE, [APP_CERT_SHA256],
                                   trusted_roots=[chain.root])
        self.assertEqual("bad_chain", ctx.exception.reason)

    def test_forged_certificate_is_rejected_in_lenient_mode_too(self):
        chain = Chain(CHALLENGE, security_level=0)
        forged, _ = chain.forge_below_leaf(CHALLENGE)
        with self.assertRaises(AttestationError) as ctx:
            verify_key_attestation(chain.b64(extra_below_leaf=forged), CHALLENGE, PACKAGE, [APP_CERT_SHA256],
                                   trusted_roots=[], require_hardware=False)
        self.assertEqual("bad_chain", ctx.exception.reason)

    def test_non_ca_intermediate_is_rejected(self):
        self.assert_reason("bad_chain", lambda: self.verify(Chain(CHALLENGE, intermediate_ca=False)))

    def test_user_auth_bound_key(self):
        self.assertTrue(self.verify(Chain(CHALLENGE, user_auth=True), require_user_auth=True).user_auth_required)

    def test_key_without_user_auth_is_rejected_when_required(self):
        self.assertFalse(self.verify(Chain(CHALLENGE)).user_auth_required)
        self.assert_reason("no_user_auth", lambda: self.verify(Chain(CHALLENGE), require_user_auth=True))

    def test_user_auth_with_timeout_is_not_per_use(self):
        self.assert_reason("no_user_auth", lambda: self.verify(
            Chain(CHALLENGE, user_auth=True, auth_timeout=300), require_user_auth=True))

    def test_google_roots_are_bundled(self):
        self.assertEqual(2, len(load_google_roots()))


if __name__ == "__main__":
    unittest.main()
