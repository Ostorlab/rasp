"""Cross-language check: the device's runtime integrity root equals the build-time root over the same `.so`.

Compiles a shared library, computes the integrity root over its code/read-only regions with the hardener
(`codehash.so_integrity_root`), then compiles a C harness against the real `integrity.c` / `sha256.c` and
asserts it derives the same root from the same file and regions. Also flips a byte in a hashed region and
asserts both sides change together — the fail-closed property. Skipped without a C compiler.
"""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import codehash

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"

LIB_SRC = r"""
static const char rodata_marker[] = "rasp-integrity-rodata-marker-0123456789";
int rasp_probe_add(int a, int b) { return a + b + (int)rodata_marker[0]; }
int rasp_probe_mul(int a, int b) { return a * b - (int)rodata_marker[1]; }
int rasp_probe_mix(int a, int b) { return (a ^ b) + rasp_probe_add(a, b) * rasp_probe_mul(a, b); }
"""

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "integrity.h"

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    rasp_file_region_t regions[64];
    size_t count = 0;
    for (int i = 2; i < argc && count < 64; i++, count++) {
        char *colon = strchr(argv[i], ':');
        if (colon == NULL) return 3;
        *colon = 0;
        regions[count].offset = strtoull(argv[i], NULL, 10);
        regions[count].length = strtoull(colon + 1, NULL, 10);
    }
    uint8_t root[32];
    if (rasp_integrity_root_from_file(argv[1], regions, count, root) != 0) { printf("ERR\n"); return 1; }
    for (int i = 0; i < 32; i++) printf("%02x", root[i]);
    printf("\n");
    return 0;
}
"""


@unittest.skipUnless(shutil.which("cc") or shutil.which("gcc"), "no C compiler")
@unittest.skipUnless(CPP.is_dir(), "native sources not present")
class IntegrityInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        compiler = shutil.which("cc") or shutil.which("gcc")
        # Build the shared library whose regions both sides hash.
        src = cls.tmp / "lib.c"
        src.write_text(LIB_SRC)
        cls.lib = cls.tmp / "libprobe.so"
        subprocess.run([compiler, "-shared", "-fPIC", "-O2", str(src), "-o", str(cls.lib)],
                       check=True, capture_output=True)
        # Build the harness against the real native integrity primitive.
        harness = cls.tmp / "harness.c"
        harness.write_text(HARNESS)
        cls.binary = cls.tmp / "harness"
        subprocess.run(
            [compiler, "-O2", "-I", str(CPP), str(harness), str(CPP / "integrity.c"), str(CPP / "sha256.c"),
             "-o", str(cls.binary)],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def native_root(self, lib_path, regions):
        args = [str(self.binary), str(lib_path)] + [f"{off}:{size}" for (off, size) in regions]
        out = subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()
        self.assertNotEqual(out, "ERR")
        return out

    def test_native_root_matches_build_time(self):
        py_root, regions = codehash.so_integrity_root(self.lib)
        self.assertGreater(len(regions), 0)  # at least .text was selected
        self.assertEqual(self.native_root(self.lib, regions), py_root)

    def test_tamper_in_a_region_changes_both_roots(self):
        py_root, regions = codehash.so_integrity_root(self.lib)
        data = bytearray(self.lib.read_bytes())
        off = regions[0][0]  # first hashed region (executable code)
        data[off] ^= 0x01
        tampered = self.tmp / "libprobe_tampered.so"
        tampered.write_bytes(data)

        py_tampered, regions2 = codehash.so_integrity_root(tampered)
        self.assertEqual(regions2, regions)  # same section layout
        self.assertNotEqual(py_tampered, py_root)  # build-time root changed
        # And the native side, over the tampered file, agrees with the new build-time root.
        self.assertEqual(self.native_root(tampered, regions), py_tampered)


if __name__ == "__main__":
    unittest.main()
