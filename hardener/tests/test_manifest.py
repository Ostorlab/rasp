"""Build-registration manifest: contents, code hashing, JSON round trip, and the trust-service handshake.

The last test is the real end-to-end: a hardener-produced manifest is loaded into the trust service's build
registry, and a report sealed with that build's key verifies. It runs only when the verifier package is
importable from the monorepo checkout; it is skipped in an isolated hardener checkout.
"""

import hashlib
import hmac
import json
import pathlib
import sys
import time
import unittest

from rasp_hardener import codehash, guardmesh
from rasp_hardener.manifest import BuildManifest, build_manifest
from rasp_hardener.seed import SEED_LEN, BuildProfile

REPO = pathlib.Path(__file__).resolve().parents[2]
CPP = REPO / "flutter_rasp" / "android" / "src" / "main" / "cpp"
VERIFIER = REPO / "verifier"

CERT = "aa" * 32
PACKAGE = "dev.ostorlab.rasp.demo_bank"


def _code_paths():
    names = ["report.c", "sha256.c", "detectors.c", "signals.c"]
    return [CPP / n for n in names if (CPP / n).exists()]


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.profile = BuildProfile.derive(bytes(range(SEED_LEN)))

    def test_manifest_fields(self):
        m = build_manifest(self.profile, package_name=PACKAGE, signing_cert_sha256=[CERT])
        self.assertEqual(m.build_id, self.profile.build_id)
        self.assertEqual(m.build_key_hex, self.profile.build_key_hex)
        self.assertEqual(m.package_name, PACKAGE)
        self.assertEqual(m.signing_cert_sha256, [CERT])
        self.assertFalse(m.revoked)
        # The seed itself must never appear in the manifest; only a fingerprint.
        self.assertNotIn(self.profile.seed_hex, m.to_json())
        self.assertEqual(m.seed_fingerprint, hashlib.sha256(self.profile.seed).hexdigest()[:16])

    @unittest.skipUnless(_code_paths(), "native sources not present")
    def test_code_hashes_and_integrity_root(self):
        paths = _code_paths()
        m = build_manifest(self.profile, package_name=PACKAGE, signing_cert_sha256=[CERT], code_paths=paths)
        self.assertEqual(set(m.code_hashes), {p.name for p in paths})
        for p in paths:
            self.assertEqual(m.code_hashes[p.name], codehash.hash_file(p))
        # The integrity root folds the code hashes and the signer digest via the guard mesh.
        expected = codehash.integrity_root(m.code_hashes, [CERT])
        self.assertEqual(m.integrity_root, expected)
        self.assertEqual(len(m.integrity_root), 64)

    @unittest.skipUnless(_code_paths(), "native sources not present")
    def test_integrity_root_changes_if_code_changes(self):
        m = build_manifest(self.profile, package_name=PACKAGE, signing_cert_sha256=[CERT],
                           code_paths=_code_paths())
        tampered = dict(m.code_hashes)
        first = next(iter(tampered))
        tampered[first] = "00" * 32
        self.assertNotEqual(codehash.integrity_root(tampered, [CERT]), m.integrity_root)

    def test_json_round_trip(self):
        m = build_manifest(self.profile, package_name=PACKAGE, signing_cert_sha256=[CERT])
        loaded = BuildManifest.from_dict(json.loads(m.to_json()))
        self.assertEqual(loaded.build_id, m.build_id)
        self.assertEqual(loaded.build_key_hex, m.build_key_hex)

    def test_write_and_load(self):
        import tempfile

        m = build_manifest(self.profile, package_name=PACKAGE, signing_cert_sha256=[CERT])
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "build_manifest.json"
            m.write(path)
            loaded = BuildManifest.load(path)
            self.assertEqual(loaded.build_key_hex, m.build_key_hex)

    @unittest.skipUnless(VERIFIER.is_dir(), "verifier package not present")
    def test_end_to_end_registration_and_report(self):
        """Hardener manifest -> trust-service registry -> a report sealed with the build key verifies."""
        if str(VERIFIER) not in sys.path:
            sys.path.insert(0, str(VERIFIER))
        try:
            from rasp_verifier.registry import BuildRegistry, RegistryError
            from rasp_verifier.report import verify_sealed_report
        except ImportError:
            self.skipTest("rasp_verifier not importable")

        m = build_manifest(self.profile, package_name=PACKAGE, signing_cert_sha256=[CERT])
        registry = BuildRegistry()
        registry.register_manifest(m.to_dict())

        build = registry.get(m.build_id)
        self.assertEqual(build.build_key, self.profile.build_key)
        self.assertEqual(build.signing_cert_sha256, [CERT])

        # Seal a report exactly as the device would (canonical JSON + HMAC with the build key).
        nonce = "Y2hhbGxlbmdl"
        report = json.dumps(
            {"v": "rasp-report-1", "buildId": m.build_id, "nonce": nonce,
             "ts": int(time.time() * 1000), "signals": []},
            separators=(",", ":"),
        )
        mac = hmac.new(build.build_key, report.encode(), hashlib.sha256).hexdigest()
        verified = verify_sealed_report({"report": report, "mac": mac}, build_key=build.build_key,
                                        expected_nonce=nonce)
        self.assertEqual(verified.build_id, m.build_id)

        # A report from a different build key is refused.
        from rasp_verifier.report import ReportError

        bad_mac = hmac.new(b"\x00" * 32, report.encode(), hashlib.sha256).hexdigest()
        with self.assertRaises(ReportError):
            verify_sealed_report({"report": report, "mac": bad_mac}, build_key=build.build_key,
                                 expected_nonce=nonce)

        # A malformed manifest is rejected at registration.
        with self.assertRaises(RegistryError):
            registry.register_manifest({"build_id": "x"})


if __name__ == "__main__":
    unittest.main()
