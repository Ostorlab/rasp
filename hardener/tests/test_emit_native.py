"""Cross-language check: the hardener's generated header decrypts on the C side, and the C guard mesh agrees.

Emits ``build_seed.h`` from a fixed seed, compiles a small C harness against the real ``strobf.c`` / ``guard.c``
/ ``sha256.c``, and asserts:

- every encrypted string in the generated table decodes to its original plaintext on the C side (so
  strenc.py and strobf.c cannot silently drift), and
- the C guard mesh computes the same integrity root as guardmesh.py over identical regions.

Mirrors verifier/tests/test_native_seal.py. Skipped when a C compiler or the native sources are unavailable.
"""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import emit
from rasp_hardener import guardmesh
from rasp_hardener import literals
from rasp_hardener import strenc
from rasp_hardener import seed

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "literals.h"
#include "strobf.h"
#include "guard.h"
#include "sha256.h"

int main(int argc, char **argv) {
    for (int slot = 0; slot < RASP_SLOT_COUNT; slot++) {
        char buf[RASP_LIT_MAXLEN + 1];
        rasp_lit_decode(slot, buf);
        printf("%s\n", buf);
    }

    if (argc > 1) {
        static uint8_t bufs[16][512];
        rasp_region_t regions[16];
        size_t count = 0;
        for (int a = 1; a < argc && count < 16; a++, count++) {
            const char *h = argv[a];
            size_t bl = strlen(h) / 2;
            for (size_t i = 0; i < bl; i++) {
                char c[3] = {h[i * 2], h[i * 2 + 1], 0};
                bufs[count][i] = (uint8_t)strtol(c, NULL, 16);
            }
            regions[count].data = bufs[count];
            regions[count].len = bl;
        }
        uint8_t root[32];
        char hex[65];
        rasp_guard_root(regions, count, root);
        rasp_hex_encode(root, 32, hex);
        printf("GUARD %s\n", hex);
    }
    return 0;
}
"""


@unittest.skipUnless(shutil.which("cc") or shutil.which("gcc"), "no C compiler")
@unittest.skipUnless(CPP.is_dir(), "native sources not present")
class EmitNativeInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.profile = seed.BuildProfile.derive(bytes(range(seed.SEED_LEN)))
        cls.lits = literals.with_build_key(literals.parse_literals(CPP / "literals.def"), cls.profile.build_key_hex)
        emit.emit_headers(cls.profile, cls.tmp, cls.lits)
        harness = cls.tmp / "harness.c"
        harness.write_text(HARNESS)
        cls.binary = cls.tmp / "harness"
        compiler = shutil.which("cc") or shutil.which("gcc")
        subprocess.run(
            [compiler, "-I", str(cls.tmp), "-I", str(CPP), str(harness),
             str(CPP / "strobf.c"), str(CPP / "literals.c"), str(CPP / "guard.c"), str(CPP / "sha256.c"), "-o", str(cls.binary)],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_harness(self, *args):
        result = subprocess.run([str(self.binary), *args], check=True, capture_output=True, text=True)
        return result.stdout.splitlines()

    def test_generated_strings_decode_on_c_side(self) -> None:
        lines = self.run_harness()
        self.assertEqual(lines, [lit.text.decode("ascii") for lit in self.lits])

    def test_c_guard_mesh_matches_python(self) -> None:
        region_hex = ["deadbeef", "00", "", "0102030405"]
        lines = self.run_harness(*region_hex)
        guard_line = next(line for line in lines if line.startswith("GUARD "))
        c_root = guard_line.split(" ", 1)[1]
        py_root = guardmesh.guard_root([bytes.fromhex(h) for h in region_hex]).hex()
        self.assertEqual(c_root, py_root)


if __name__ == "__main__":
    unittest.main()
