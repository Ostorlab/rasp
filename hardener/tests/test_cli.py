"""CLI: gen-build emits headers + manifest, show is non-secret, register emits a manifest."""

import json
import pathlib
import tempfile
import unittest

from rasp_hardener import cli
from rasp_hardener.seed import BuildProfile

SEED_HEX = "000102030405060708090a0b0c0d0e0f"


class CliTest(unittest.TestCase):
    def test_gen_build_emits_headers_and_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            cpp = d / "cpp"
            cpp.mkdir()
            (cpp / "report.c").write_text("int x;\n")  # something to hash
            manifest_path = d / "build_manifest.json"
            rc = cli.main(
                ["gen-build", "--seed", SEED_HEX, "--cpp-dir", str(cpp),
                 "--cert", "aa" * 32, "--manifest", str(manifest_path)]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((cpp / "build_generated.h").exists())
            self.assertTrue((cpp / "build_seed.h").exists())

            profile = BuildProfile.derive(bytes.fromhex(SEED_HEX))
            generated = (cpp / "build_generated.h").read_text()
            self.assertIn(profile.build_id, generated)
            self.assertIn(profile.build_key_hex, generated)

            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["build_id"], profile.build_id)
            self.assertIn("report.c", manifest["code_hashes"])
            self.assertEqual(len(manifest["integrity_root"]), 64)

    def test_show_is_non_secret(self):
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["show", "--seed", SEED_HEX])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        profile = BuildProfile.derive(bytes.fromhex(SEED_HEX))
        self.assertEqual(out["build_id"], profile.build_id)
        self.assertNotIn(profile.build_key_hex, buf.getvalue())

    def test_register_to_stdout(self):
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["register", "--seed", SEED_HEX, "--cpp-dir", "/nonexistent",
                           "--cert", "bb" * 32])
        self.assertEqual(rc, 0)
        manifest = json.loads(buf.getvalue())
        profile = BuildProfile.derive(bytes.fromhex(SEED_HEX))
        self.assertEqual(manifest["build_key_hex"], profile.build_key_hex)
        self.assertEqual(manifest["signing_cert_sha256"], ["bb" * 32])

    def test_bad_seed_length_exits(self):
        with self.assertRaises(SystemExit):
            cli.main(["show", "--seed", "00"])


if __name__ == "__main__":
    unittest.main()
