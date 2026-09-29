"""Acceptance gate: the hardened binary yields no protected plaintext and no meaningful symbol names.

Builds the core as a host shared library from a fixed seed's generated headers, then:
  a) byte-scans the library for registry plaintexts (>= 4 decoded bytes) and forbidden name patterns;
  b) byte-scans for every original symbol name from symbols.def (covers .symtab/.strtab/.dynstr);
  c) after strip, asserts the dynamic export set is a subset of JNI_OnLoad/JNI_OnUnload;
  d) smoke-runs the report builder under hardened headers and byte-compares its JSON with the dev build,
     proving the decrypted keys are wire-valid and encryption is invisible on the wire.

The core gate needs only a C compiler. With a JDK, a second gate compiles and scans JNI too.
"""

import hashlib
import hmac
import json
import re
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import emit
from rasp_hardener import names
from rasp_hardener import literals
from rasp_hardener import seed

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"
SOURCES = ["detectors.c", "signals.c", "sha256.c", "report.c", "guard.c", "strobf.c", "literals.c",
           "integrity.c", "wbaes.c", "securestore.c"]

SMOKE = r"""
#include <stdio.h>
#include "report.h"
#include "signals.h"

int main(void) {
    rasp_signal_list_t list = {.count = 0};
    rasp_signals_add(&list, RASP_THREAT_ROOT, "native.su_binary", 90, "/system/bin/su");
    char out[4096];
    if (rasp_signals_to_report_json(&list, out, sizeof(out)) < 0) return 1;
    printf("%s\n", out);
    return 0;
}
"""

# The one signal in SMOKE uses a raw detector id/evidence on purpose: the smoke measures the JSON wire
# format produced by the registry-backed builder, not the detectors' own literals.
FORBIDDEN_PATTERNS = [b"rasp_", b"RASP_", b"Java_", b"DEV_LIT"]


class HygieneGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("cc") is None and shutil.which("gcc") is None:
            raise unittest.SkipTest("no C compiler")
        cls.cc = os.environ.get("CC") or ("gcc" if shutil.which("gcc") else "cc")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.profile = seed.BuildProfile.derive(bytes(range(seed.SEED_LEN)))
        cls.lits = literals.with_build_key(literals.parse_literals(CPP / "literals.def"), cls.profile.build_key_hex)
        cls.symbols = names.parse_symbols(CPP / "symbols.def")
        emit.emit_headers(cls.profile, cls.tmp, cls.lits)
        (cls.tmp / "build_names.h").write_text(emit.render_build_names_h(cls.profile, cls.symbols))
        cls.so = cls.tmp / "librasp_core.so"
        subprocess.run(
            [cls.cc, "-shared", "-fPIC", "-fvisibility=hidden", "-O2", "-Wall", "-Wextra", "-Werror",
             "-I", str(cls.tmp), "-I", str(CPP), "-o", str(cls.so)] + [str(CPP / s) for s in SOURCES],
            check=True,
        )
        cls.data = cls.so.read_bytes()

    def testNoRegistryPlaintext_survives(self) -> None:
        for lit in self.lits:
            if len(lit.text) >= 4:
                self.assertFalse(lit.text in self.data, lit.name)

    def testNoForbiddenNamePatterns(self) -> None:
        for pattern in FORBIDDEN_PATTERNS:
            self.assertNotIn(pattern, self.data)

    def testNoOriginalSymbolNames_survive(self) -> None:
        output = subprocess.run(["nm", "--defined-only", str(self.so)], check=True, capture_output=True, text=True).stdout
        defined = {line.split()[-1].split(".")[0] for line in output.splitlines()}
        self.assertEqual(defined.intersection(self.symbols), set())
        for sym in self.symbols:
            if len(sym) >= 4:
                self.assertFalse(sym.encode("ascii") in self.data, sym)

    def testStrippedExportSet_isJniOnly(self) -> None:
        stripped = self.tmp / "librasp_core_stripped.so"
        subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(self.so)], check=True)
        out = subprocess.run(["nm", "-D", "--defined-only", str(stripped)],
                             capture_output=True, text=True, check=True).stdout
        exported = {line.split()[-1] for line in out.splitlines() if line.strip()}
        self.assertLessEqual(exported, {"JNI_OnLoad", "JNI_OnUnload"})

    def testHardenedJson_matchesDevByteForByte(self) -> None:
        harness = self.tmp / "smoke.c"
        harness.write_text(SMOKE)
        hardened_bin = self.tmp / "smoke_hardened"
        subprocess.run([self.cc, "-I", str(self.tmp), "-I", str(CPP), str(harness)]
                       + [str(CPP / s) for s in SOURCES] + ["-o", str(hardened_bin)], check=True)
        dev_bin = self.tmp / "smoke_dev"
        subprocess.run([self.cc, "-I", str(CPP), str(harness)]
                       + [str(CPP / s) for s in SOURCES] + ["-o", str(dev_bin)], check=True)
        run = lambda b: subprocess.run([str(b)], check=True, capture_output=True, text=True).stdout
        hardened_out = run(hardened_bin)
        self.assertEqual(hardened_out, run(dev_bin))
        self.assertIn('"detector":"native.su_binary"', hardened_out)

    def testSymbolsMap_roundTrips(self) -> None:
        mapping = emit.render_symbols_map(self.profile, self.symbols)
        self.assertEqual(set(mapping.values()), set(self.symbols))
        self.assertTrue(all(k.startswith("r") and len(k) == 9 for k in mapping))


    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp)

    def testCompiledSymbols_everyPrivateDefinitionIsCovered(self) -> None:
        # -O0 prevents optimizer inlining from concealing omissions in symbols.def.
        for source in SOURCES:
            obj = self.tmp / (source + ".o")
            subprocess.run([self.cc, "-O0", "-I", str(CPP), "-c", str(CPP / source), "-o", str(obj)], check=True)
            output = subprocess.run(["nm", "--defined-only", str(obj)], check=True, text=True, capture_output=True).stdout
            for line in output.splitlines():
                symbol = line.split()[-1].split(".")[0]
                if symbol.startswith("r_") is False:
                    self.assertIn(symbol, self.symbols, source)

    def testOptimizedLtoBuild_noProtectedPlaintext(self) -> None:
        library = self.tmp / "lto.so"
        subprocess.run([self.cc, "-shared", "-fPIC", "-fvisibility=hidden", "-O3", "-flto",
                        "-I", str(self.tmp), "-I", str(CPP), "-o", str(library)]
                       + [str(CPP / source) for source in SOURCES], check=True)
        # Keep symbols reachable under LTO by linking a harness, too.
        harness = self.tmp / "lto.c"
        harness.write_text('#include "literals.h"\n#include <stdio.h>\nint main(void) { char b[RASP_LIT_MAXLEN+1]; for(int i=0;i<RASP_SLOT_COUNT;i++){rasp_lit_decode(i,b);puts(b);}return 0;}')
        binary = self.tmp / "lto"
        subprocess.run([self.cc, "-O3", "-flto", "-I", str(self.tmp), "-I", str(CPP), str(harness),
                        str(CPP / "literals.c"), str(CPP / "strobf.c"), "-o", str(binary)], check=True)
        for artifact in [library, binary]:
            data = artifact.read_bytes()
            for lit in self.lits:
                if len(lit.text) >= 4:
                    self.assertFalse(lit.text in data, lit.name)
        output = subprocess.run([str(binary)], check=True, capture_output=True).stdout.splitlines()
        self.assertEqual(output, [lit.text for lit in self.lits])

    def testSealEnvelope_hardenedMatchesDevAndHmac(self) -> None:
        # Supply deterministic detector inputs; live host detectors can legitimately change between runs.
        harness = self.tmp / "seal.c"
        harness.write_text(SEAL)
        results = []
        for mode in ["dev", "hardened"]:
            binary = self.tmp / ("seal_" + mode)
            includes = ["-I", str(self.tmp)] if mode == "hardened" else []
            subprocess.run([self.cc, "-O2", *includes, "-I", str(CPP), str(harness)]
                           + [str(CPP / source) for source in SOURCES if source != "detectors.c"]
                           + ["-o", str(binary)], check=True)
            results.append(subprocess.run([str(binary)], check=True, capture_output=True).stdout)
        self.assertEqual(results[0], results[1])
        envelope = json.loads(results[0])
        expected = hmac.new(bytes(range(32)), envelope["report"].encode(), hashlib.sha256).hexdigest()
        self.assertEqual(envelope["mac"], expected)
        report = json.loads(envelope["report"])
        self.assertEqual(report["nonce"], 'nonce"\\\n')
        self.assertEqual(len(report["signals"]), 2)
        self.assertEqual(report["signals"][0]["detector"], "native.su_binary")
        self.assertEqual(report["signals"][1]["detector"], "managed.test")

    def testJniLibrary_releaseExportsAndPlaintext(self) -> None:
        javac = shutil.which("javac")
        if javac is None:
            self.skipTest("JDK unavailable; core binary gate still runs")
        include = pathlib.Path(javac).resolve().parents[1] / "include"
        if (include / "jni.h").exists() is False:
            self.skipTest("JDK JNI headers unavailable")
        (self.tmp / "integrity_regions.h").write_text(emit.render_integrity_regions_h([(0, 32)]))
        library = self.tmp / "jni.so"
        subprocess.run([self.cc, "-shared", "-fPIC", "-fvisibility=hidden", "-O2", "-Wl,--strip-all", "-Wl,--no-undefined-version", "-Wl,--version-script=" + str(CPP / "exports.map"),
                        "-Wall", "-Wextra", "-Werror", "-I", str(include), "-I", str(include / "linux"),
                        "-I", str(self.tmp), "-I", str(CPP), "-o", str(library)]
                       + [str(CPP / source) for source in SOURCES + ["rasp_jni.c"]], check=True)
        output = subprocess.run(["nm", "-D", "--defined-only", str(library)], check=True, capture_output=True, text=True).stdout
        self.assertEqual({line.split()[-1] for line in output.splitlines()}, {"JNI_OnLoad"})
        data = library.read_bytes()
        for lit in self.lits:
            if len(lit.text) >= 4:
                self.assertFalse(lit.text in data, lit.name)
        for pattern in FORBIDDEN_PATTERNS:
            self.assertFalse(pattern in data, pattern)


SEAL = r"""
#include <stdio.h>
#include "detectors.h"
#include "report.h"
void rasp_run_all(rasp_signal_list_t *list) {
    RASP_LIT(SIG_SU_BIN, detector);
    RASP_LIT(SU_PATH_1, evidence);
    rasp_signals_add(list, RASP_THREAT_ROOT, detector, 90, evidence);
}
int main(void) {
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    char out[8192];
    if (rasp_seal_report("[{\"threat\":\"tamper\",\"confidence\":75,\"detector\":\"managed.test\",\"evidence\":\"x\"}]",
                         "nonce\"\\\n", 123456789, "test-build", key, 32, out, sizeof(out)) <= 0) return 1;
    puts(out);
    return 0;
}
"""
