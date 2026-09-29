"""Cross-language check: the native core seals a report that the Python trust service accepts.

Compiles a tiny C harness against the real native sources, seals a report with a known build key and nonce,
and verifies it with `verify_sealed_report`. This proves the device's HMAC and the server's agree byte for
byte. Skipped when a C compiler or the native sources are unavailable.
"""

import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

from rasp_verifier.report import ReportError, verify_sealed_report

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"
BUILD_KEY = bytes(range(32))

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include "report.h"
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    char out[8192];
    int n = rasp_seal_report("[{\"threat\":\"tamper\",\"confidence\":90,\"detector\":\"platform.signing_cert\",\"evidence\":\"x\"}]",
                             argv[1], atoll(argv[2]), "test-build", key, sizeof(key), out, sizeof(out));
    if (n <= 0) return 1;
    fputs(out, stdout);
    return 0;
}
"""


@unittest.skipUnless(shutil.which("cc") or shutil.which("gcc"), "no C compiler")
@unittest.skipUnless(CPP.is_dir(), "native sources not present")
class NativeSealInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        harness = pathlib.Path(cls.tmp) / "harness.c"
        harness.write_text(HARNESS)
        cls.binary = pathlib.Path(cls.tmp) / "harness"
        compiler = shutil.which("cc") or shutil.which("gcc")
        subprocess.run(
            [compiler, "-I", str(CPP), str(harness), str(CPP / "report.c"), str(CPP / "signals.c"), str(CPP / "literals.c"), str(CPP / "strobf.c"),
             str(CPP / "detectors.c"), str(CPP / "sha256.c"), "-o", str(cls.binary)],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def seal(self, nonce, ts_ms):
        result = subprocess.run([str(self.binary), nonce, str(ts_ms)], check=True, capture_output=True)
        import json

        return json.loads(result.stdout)

    def test_native_report_verifies_in_python(self):
        nonce = "Y2hhbGxlbmdlLW5vbmNl"
        envelope = self.seal(nonce, int(time.time() * 1000))
        report = verify_sealed_report(envelope, build_key=BUILD_KEY, expected_nonce=nonce)
        self.assertEqual(report.build_id, "test-build")
        self.assertIn("tamper", report.threats)

    def test_wrong_build_key_is_rejected(self):
        nonce = "bm9uY2U"
        envelope = self.seal(nonce, int(time.time() * 1000))
        with self.assertRaises(ReportError) as cm:
            verify_sealed_report(envelope, build_key=b"\x00" * 32, expected_nonce=nonce)
        self.assertEqual(cm.exception.reason, "bad_mac")

    def test_stale_report_is_rejected(self):
        nonce = "c3RhbGU"
        envelope = self.seal(nonce, int((time.time() - 3600) * 1000))
        with self.assertRaises(ReportError) as cm:
            verify_sealed_report(envelope, build_key=BUILD_KEY, expected_nonce=nonce)
        self.assertEqual(cm.exception.reason, "stale")


if __name__ == "__main__":
    unittest.main()
