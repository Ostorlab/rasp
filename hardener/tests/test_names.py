"""Tests for per-build symbol renaming (rasp_hardener.names)."""

import pathlib
import re
import tempfile
import unittest

from rasp_hardener import names
from rasp_hardener import emit
from rasp_hardener import seed

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"


class PseudonymTest(unittest.TestCase):
    def testDeterministic_perKey(self) -> None:
        key = b"\x01" * 32
        self.assertEqual(names.pseudonym("rasp_seal_report", key), names.pseudonym("rasp_seal_report", key))

    def testDistinctPerNameAndKey(self) -> None:
        key = b"\x01" * 32
        self.assertNotEqual(names.pseudonym("rasp_seal_report", key), names.pseudonym("rasp_sha256", key))
        self.assertNotEqual(names.pseudonym("rasp_seal_report", key), names.pseudonym("rasp_seal_report", b"\x02" * 32))

    def testValidCIdentifier_rPrefix(self) -> None:
        p = names.pseudonym("rasp_seal_report", b"\x01" * 32)
        self.assertRegex(p, r"^r[0-9a-f]{8}$")

    def testCollision_raises(self) -> None:
        def fake(name: str, key: bytes) -> str:
            return "r00000000"
        with self.assertRaises(ValueError):
            names.rename_map(["a", "b"], b"\x01" * 32, derive=fake)


class SymbolsDefTest(unittest.TestCase):
    def testSymbolsDef_parsesUniqueNames(self) -> None:
        syms = names.parse_symbols(CPP / "symbols.def")
        self.assertGreater(len(syms), 50)
        self.assertEqual(len(syms), len(set(syms)))
        self.assertIn("rasp_seal_report", syms)
        self.assertIn("rasp_lit_decode", syms)
        self.assertNotIn("JNI_OnLoad", syms)

    def testSymbolsDef_coversEveryHeaderFunction(self) -> None:
        syms = set(names.parse_symbols(CPP / "symbols.def"))
        for header in CPP.glob("*.h"):
            if header.name in ("hardening.h", "literals.h", "build_config.h"):
                continue
            for m in re.finditer(r"\b(rasp_[a-z0-9_]+)\s*\(", header.read_text()):
                self.assertIn(m.group(1), syms, f"{header.name}: {m.group(1)}")


class RenameMapTest(unittest.TestCase):
    def testRenderBuildNamesH_definesEverySymbol(self) -> None:
        profile = seed.BuildProfile.derive(bytes(range(seed.SEED_LEN)))
        syms = names.parse_symbols(CPP / "symbols.def")
        text = emit.render_build_names_h(profile, syms)
        for sym in syms:
            self.assertIn(f"#define {sym} ", text)
        self.assertIn("#ifndef RASP_BUILD_NAMES_H", text)


class RegistryValidationTest(unittest.TestCase):
    def testSymbols_duplicateNames_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "symbols.def"
            path.write_text("RASP_SYMBOL(thing)\nRASP_SYMBOL(thing)\n")
            with self.assertRaises(ValueError):
                names.parse_symbols(path)
