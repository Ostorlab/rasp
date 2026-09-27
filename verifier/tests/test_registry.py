"""Build registry ingestion of a hardener build manifest (design §6 build registration)."""

import unittest

from rasp_verifier.registry import Build, BuildRegistry, RegistryError
from rasp_verifier.report import ReportError, verify_sealed_report

from .helpers import seal_report

MANIFEST = {
    "version": "raxp-build-manifest-1",
    "build_id": "b-0f5d425c5e79",
    "build_key_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "package_name": "dev.ostorlab.rasp.demo_bank",
    "signing_cert_sha256": ["aa" * 32],
    "code_hashes": {"report.c": "11" * 32, "sha256.c": "22" * 32},
    "integrity_root": "33" * 32,
    "seed_fingerprint": "0011223344556677",
    "revoked": False,
}


class RegistryManifestTest(unittest.TestCase):
    def test_from_manifest_populates_fields(self):
        build = Build.from_manifest(MANIFEST)
        self.assertEqual(build.build_id, MANIFEST["build_id"])
        self.assertEqual(build.build_key.hex(), MANIFEST["build_key_hex"])
        self.assertEqual(build.package_name, MANIFEST["package_name"])
        self.assertEqual(build.signing_cert_sha256, MANIFEST["signing_cert_sha256"])
        self.assertEqual(build.code_hashes, MANIFEST["code_hashes"])
        self.assertEqual(build.integrity_root, MANIFEST["integrity_root"])
        self.assertFalse(build.revoked)

    def test_register_manifest_and_get(self):
        registry = BuildRegistry()
        registry.register_manifest(MANIFEST)
        build = registry.get(MANIFEST["build_id"])
        self.assertEqual(build.build_key.hex(), MANIFEST["build_key_hex"])

    def test_report_sealed_with_manifest_key_verifies(self):
        registry = BuildRegistry()
        registry.register_manifest(MANIFEST)
        build = registry.get(MANIFEST["build_id"])
        nonce = "Y2hhbGxlbmdl"
        envelope = seal_report(nonce, build_id=build.build_id, build_key=build.build_key)
        report = verify_sealed_report(envelope, build_key=build.build_key, expected_nonce=nonce)
        self.assertEqual(report.build_id, build.build_id)

    def test_report_with_wrong_key_refused(self):
        registry = BuildRegistry()
        registry.register_manifest(MANIFEST)
        build = registry.get(MANIFEST["build_id"])
        nonce = "Y2hhbGxlbmdl"
        envelope = seal_report(nonce, build_id=build.build_id, build_key=b"\x00" * 32)
        with self.assertRaises(ReportError) as cm:
            verify_sealed_report(envelope, build_key=build.build_key, expected_nonce=nonce)
        self.assertEqual(cm.exception.reason, "bad_mac")

    def test_bad_manifest_rejected(self):
        registry = BuildRegistry()
        with self.assertRaises(RegistryError) as cm:
            registry.register_manifest({"build_id": "x"})  # no build_key_hex
        self.assertEqual(cm.exception.reason, "bad_manifest")

    def test_revoked_manifest_build_refused_on_get(self):
        registry = BuildRegistry()
        registry.register_manifest({**MANIFEST, "revoked": True})
        with self.assertRaises(RegistryError) as cm:
            registry.get(MANIFEST["build_id"])
        self.assertEqual(cm.exception.reason, "revoked_build")


if __name__ == "__main__":
    unittest.main()
