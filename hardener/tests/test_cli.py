"""CLI: gen-build emits headers + manifest, show is non-secret, register emits a manifest."""

import contextlib
import io
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import aes
from rasp_hardener import cli
from rasp_hardener import codehash
from rasp_hardener import whitebox
from rasp_hardener.seed import BuildProfile

SEED_HEX = "000102030405060708090a0b0c0d0e0f"


class CliTest(unittest.TestCase):
    def test_gen_build_emits_headers_and_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            cpp = d / "cpp"
            cpp.mkdir()
            real_cpp = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp/android/src/main/cpp"
            for registry in ["literals.def", "symbols.def"]:
                shutil.copy(real_cpp / registry, cpp / registry)
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
            self.assertNotIn(profile.build_key_hex, generated)
            self.assertNotIn(profile.build_key_hex, (cpp / "build_seed.h").read_text())
            self.assertNotIn("native.", (cpp / "build_seed.h").read_text())
            mapping = json.loads((cpp / "symbols.map").read_text())
            self.assertIn("rasp_seal_report", mapping.values())
            self.assertIn("#define rasp_seal_report ", (cpp / "build_names.h").read_text())

            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["build_id"], profile.build_id)
            self.assertIn("report.c", manifest["code_hashes"])
            self.assertEqual(len(manifest["integrity_root"]), 64)

    def test_show_is_non_secret(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["show", "--seed", SEED_HEX])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        profile = BuildProfile.derive(bytes.fromhex(SEED_HEX))
        self.assertEqual(out["build_id"], profile.build_id)
        self.assertEqual(out["seed_fingerprint"], profile.seed_fingerprint)
        # Neither the build key nor the raw seed (which derives it) may appear in the output.
        self.assertNotIn(profile.build_key_hex, buf.getvalue())
        self.assertNotIn(SEED_HEX, buf.getvalue())

    def test_register_to_stdout(self):
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

    def test_gen_wbkey_emits_tables(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "wbaes_tables.h"
            key = "0f0e0d0c0b0a09080706050403020100"
            rc = cli.main(["gen-wbkey", "--key", key, "--out", str(out)])
            self.assertEqual(rc, 0)
            header = out.read_text()
            self.assertIn("RASP_WBAES_TYPE2[9][16][256]", header)
            self.assertNotIn(key, header)  # key is not a contiguous literal
            # The emitted tables reproduce a reference AES encryption.
            probe = bytes(range(16))
            self.assertEqual(
                whitebox.generate(bytes.fromhex(key)).encrypt_block(probe),
                aes.encrypt_block_key(bytes.fromhex(key), probe),
            )

    def test_gen_wbkey_bad_key_length_exits(self):
        with self.assertRaises(SystemExit):
            cli.main(["gen-wbkey", "--key", "00", "--out", "/dev/null"])

    @unittest.skipUnless(shutil.which("cc") or shutil.which("gcc"), "no C compiler")
    def test_gen_build_with_so_emits_integrity_regions(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            src = d / "lib.c"
            src.write_text("int f(int a){ return a + 1; }\n")
            lib = d / "lib.so"
            compiler = shutil.which("cc") or shutil.which("gcc")
            subprocess.run([compiler, "-shared", "-fPIC", "-O2", str(src), "-o", str(lib)],
                           check=True, capture_output=True)
            cpp = d / "cpp"
            cpp.mkdir()
            real_cpp = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp/android/src/main/cpp"
            for registry in ["literals.def", "symbols.def"]:
                shutil.copy(real_cpp / registry, cpp / registry)
            manifest_path = d / "build_manifest.json"
            rc = cli.main(
                ["gen-build", "--seed", SEED_HEX, "--cpp-dir", str(cpp), "--so", str(lib),
                 "--manifest", str(manifest_path)]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((cpp / "integrity_regions.h").exists())
            header = (cpp / "integrity_regions.h").read_text()
            self.assertIn("RASP_INTEGRITY_REGIONS[]", header)

            manifest = json.loads(manifest_path.read_text())
            expected_root, expected_regions = codehash.so_integrity_root(lib)
            self.assertEqual(manifest["integrity_root"], expected_root)
            self.assertEqual(len(manifest["integrity_regions"]), len(expected_regions))
            self.assertEqual(header.count("ULL, "), len(expected_regions))


class ResourceCliTest(unittest.TestCase):
    def testResourceAndVm_roundTrip_outputsLoadableArtifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp = pathlib.Path(directory)
            key, plain, package, opened = [tmp / name for name in ["key", "plain", "package", "opened"]]
            key.write_bytes(bytes(range(32)))
            plain.write_bytes(b"private asset")
            common = ["--key-file", str(key), "--guard-root", "ab" * 32, "--identity", "asset.bin"]
            self.assertEqual(cli.main(["pack-asset", *common, "--input", str(plain), "--out", str(package), "--tables", str(tmp / "tables.h")]), 0)
            self.assertEqual(cli.main(["open-asset", *common, "--input", str(package), "--out", str(opened)]), 0)
            self.assertEqual(opened.read_bytes(), plain.read_bytes())
            self.assertTrue((tmp / "tables.h").read_text().startswith("/* Generated"))
            self.assertEqual(cli.main(["compile-vm", "--seed", SEED_HEX, "--expression", "r0 + r1", "--out", str(tmp / "vm")]), 0)
            self.assertEqual(len((tmp / "vm").read_bytes()), 32)


if __name__ == "__main__":
    unittest.main()
