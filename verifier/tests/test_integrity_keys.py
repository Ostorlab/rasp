"""Integrity-derived report sealing (design §8): tamper fails closed at the server.

The device MACs the report with a key derived from the guard-mesh root over its code regions; the server
derives the same key from the integrity root registered for the build. When the runtime root matches the
registered one (untampered code) the report verifies; a different runtime root — a patched binary — yields a
different derived key, so the MAC no longer matches and the report is refused with no on-device branch.
"""

import hashlib
import hmac
import unittest

from rasp_verifier.report import ReportError, verify_sealed_report

from tests.helpers import BUILD_KEY, seal_report

# The integrity root registered for the build at hardening time (hex).
REGISTERED_ROOT = "42d544dbe00b9b6a4e567625542fc3b155a72f23a2b5e20d6308bf7690d0dc5f"


def derived_key(build_key: bytes, root_hex: str) -> bytes:
    return hmac.new(build_key, bytes.fromhex(root_hex), hashlib.sha256).digest()


class IntegrityKeyTest(unittest.TestCase):
    def test_untampered_report_verifies(self):
        nonce = "aW50ZWdyaXR5"
        # Device seals with the key derived from its (matching) runtime root.
        envelope = seal_report(nonce, build_key=derived_key(BUILD_KEY, REGISTERED_ROOT))
        report = verify_sealed_report(
            envelope, build_key=BUILD_KEY, expected_nonce=nonce, integrity_root=REGISTERED_ROOT
        )
        self.assertEqual(report.nonce, nonce)

    def test_tampered_binary_fails_closed(self):
        nonce = "aW50ZWdyaXR5"
        # A patched binary derives a different runtime root, so it seals with a different key...
        tampered_root = "8c1c54f8b5ebf5d74cb99ea4feb0c638d040b7985cec24dd7848126ab4ff0a71"
        envelope = seal_report(nonce, build_key=derived_key(BUILD_KEY, tampered_root))
        # ...but the server derives the key from the REGISTERED root, so the MAC does not match.
        with self.assertRaises(ReportError) as cm:
            verify_sealed_report(
                envelope, build_key=BUILD_KEY, expected_nonce=nonce, integrity_root=REGISTERED_ROOT
            )
        self.assertEqual(cm.exception.reason, "bad_mac")

    def test_raw_key_report_rejected_when_integrity_expected(self):
        nonce = "aW50ZWdyaXR5"
        # A report sealed with the raw build key (no derivation) must not pass an integrity-required check.
        envelope = seal_report(nonce, build_key=BUILD_KEY)
        with self.assertRaises(ReportError) as cm:
            verify_sealed_report(
                envelope, build_key=BUILD_KEY, expected_nonce=nonce, integrity_root=REGISTERED_ROOT
            )
        self.assertEqual(cm.exception.reason, "bad_mac")

    def test_default_path_unaffected(self):
        # With no integrity_root, the raw build key is used exactly as before.
        nonce = "aW50ZWdyaXR5"
        envelope = seal_report(nonce, build_key=BUILD_KEY)
        report = verify_sealed_report(envelope, build_key=BUILD_KEY, expected_nonce=nonce)
        self.assertEqual(report.nonce, nonce)

    def test_bad_integrity_root_hex(self):
        nonce = "aW50ZWdyaXR5"
        envelope = seal_report(nonce, build_key=BUILD_KEY)
        with self.assertRaises(ReportError) as cm:
            verify_sealed_report(
                envelope, build_key=BUILD_KEY, expected_nonce=nonce, integrity_root="zznothex"
            )
        self.assertEqual(cm.exception.reason, "bad_integrity_root")


if __name__ == "__main__":
    unittest.main()
