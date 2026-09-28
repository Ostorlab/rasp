"""Executable LLVM 18 pass contract; set LLVM_HOME to enable toolchain tests."""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LLVM = pathlib.Path(os.environ.get("LLVM_HOME", "/nonexistent"))
SOURCE = r'''
#include <stdint.h>
#include <stdio.h>
uint64_t rasp_guard_probe(uint64_t site) { (void)site; return 0; }
uint32_t compute(uint32_t x, uint32_t y) {
    uint32_t z = x + y;
    if (x & 1) z ^= x; else z -= y;
    for (uint32_t i = 0; i < (y & 7); i++) z += i ^ x;
    return z;
}
int main(void) {
    for (uint32_t x = 0; x < 250; x++)
        for (uint32_t y = 0; y < 35; y++) printf("%u\n", compute(x * 9876543U, y));
    return 0;
}
'''


@unittest.skipUnless((LLVM / "bin/opt").is_file(), "LLVM_HOME with LLVM 18 required")
class CompilerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.tmp = pathlib.Path(cls.directory.name)
        cls.plugin = cls.tmp / "RaspPass.so"
        subprocess.run([str(ROOT / "hardener/compiler/build.sh"), str(cls.plugin)], check=True)
        source = cls.tmp / "input.c"
        source.write_text(SOURCE)
        cls.ir = cls.tmp / "input.ll"
        subprocess.run([str(LLVM / "bin/clang"), "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm", str(source), "-o", str(cls.ir)], check=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def transform(self, source: pathlib.Path, build_seed: str = "123") -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ, RASP_FUNCTIONS="compute", RASP_SEED=build_seed)
        return subprocess.run([str(LLVM / "bin/opt"), "-load-pass-plugin", str(self.plugin), "-passes=rasp-harden", "-verify-each", "-S", str(source), "-o", "-"], env=environment, capture_output=True, text=True)

    def testTransform_branchesLoops_matchOriginalAndVaryBySeed(self) -> None:
        result = self.transform(self.ir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("switch i32", result.stdout)
        self.assertIn("call i64 @rasp_guard_probe", result.stdout)
        self.assertNotEqual(result.stdout, self.transform(self.ir, "456").stdout)
        transformed = self.tmp / "output.ll"
        transformed.write_text(result.stdout)
        results = []
        for source in [self.ir, transformed]:
            binary = self.tmp / (source.stem + ".bin")
            subprocess.run([str(LLVM / "bin/clang"), str(source), "-o", str(binary)], check=True)
            results.append(subprocess.run([str(binary)], check=True, capture_output=True).stdout)
        self.assertEqual(results[0], results[1])

    def testTransform_unsupportedSwitch_rejected(self) -> None:
        source = self.tmp / "switch.ll"
        source.write_text('define i32 @compute(i32 %x) { entry: switch i32 %x, label %b [i32 1, label %a]\na: ret i32 2\nb: ret i32 3\n}\n')
        result = self.transform(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported terminator", result.stderr)

    def testTransform_missingSelectedFunction_rejected(self) -> None:
        source = self.tmp / "missing.ll"
        source.write_text('define i32 @other() { ret i32 1 }\n')
        result = self.transform(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected function not found", result.stderr)

    def testWeaving_configuredRegionMutation_changesResult(self) -> None:
        cpp = ROOT / "flutter_rasp/android/src/main/cpp"
        source = self.tmp / "woven.c"
        source.write_text(r"""
#include <stdio.h>
#include "weave.h"
unsigned compute(unsigned x) { return x + 123; }
int main(void) {
    unsigned char bytes[4] = {1,2,3,4}, expected[32];
    rasp_region_t region = {bytes, sizeof(bytes)};
    if (rasp_guard_probe(7) == 0) return 1;
    rasp_guard_root(&region, 1, expected);
    if (rasp_weave_configure(&region, 1, expected) != 0) return 2;
    if (compute(9) != 132) return 3;
    bytes[0] ^= 1;
    if (compute(9) == 132) return 4;
    puts("woven mutation rejected");
    return 0;
}
""")
        ir = self.tmp / "woven.ll"
        subprocess.run([str(LLVM / "bin/clang"), "-O0", "-Xclang", "-disable-O0-optnone", "-I", str(cpp), "-S", "-emit-llvm", str(source), "-o", str(ir)], check=True)
        result = self.transform(ir)
        self.assertEqual(result.returncode, 0, result.stderr)
        ir.write_text(result.stdout)
        binary = self.tmp / "woven"
        subprocess.run([str(LLVM / "bin/clang"), str(ir)] + [str(cpp / name) for name in ["weave.c", "guard.c", "sha256.c"]] + ["-o", str(binary)], check=True)
        self.assertEqual(subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout.strip(), "woven mutation rejected")
