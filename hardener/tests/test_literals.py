"""Tests for the literal registry (literals.def) and its parser (rasp_hardener.literals)."""

import pathlib
import tempfile
import unittest

from rasp_hardener import literals

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"
REGISTRY = CPP / "literals.def"


class UnescapeCTest(unittest.TestCase):
    def testPlain_ascii_staysBytes(self) -> None:
        self.assertEqual(literals.unescape_c("native.su_binary"), b"native.su_binary")

    def testEscapes_decodeToBytes(self) -> None:
        self.assertEqual(literals.unescape_c('{\\"threat\\":\\"%s\\"'), b'{"threat":"%s"')
        self.assertEqual(literals.unescape_c("\\\\%c"), b"\\%c")
        self.assertEqual(literals.unescape_c("a\\nb\\tc\\rd"), b"a\nb\tc\rd")

    def testUnsupportedEscape_raises(self) -> None:
        with self.assertRaises(ValueError):
            literals.unescape_c("\\x41")
        with self.assertRaises(ValueError):
            literals.unescape_c("\\u0041")
        with self.assertRaises(ValueError):
            literals.unescape_c("trailing\\")

    def testQuoteEscape_keepsQuote(self) -> None:
        self.assertEqual(literals.unescape_c('a\\"b'), b'a"b')


class ParseRegistryTest(unittest.TestCase):
    def testRealRegistry_parsesUniqueNames(self) -> None:
        lits = literals.parse_literals(REGISTRY)
        self.assertGreater(len(lits), 80)
        names = [lit.name for lit in lits]
        self.assertEqual(len(names), len(set(names)))

    def testRealRegistry_containsKnownEntries(self) -> None:
        by_name = literals.literals_by_name(literals.parse_literals(REGISTRY))
        self.assertEqual(by_name["TRACER_LABEL"].text, b"TracerPid:")
        self.assertEqual(by_name["SIG_SU_BIN"].text, b"native.su_binary")
        self.assertEqual(by_name["BUILD_KEY_HEX"].text,
                         b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

    def testRealRegistry_everyTextFitsDevBound(self) -> None:
        for lit in literals.parse_literals(REGISTRY):
            self.assertLessEqual(len(lit.text), literals.MAX_TEXT_LEN, lit.name)

    def testRealRegistry_allTextsAreAscii(self) -> None:
        for lit in literals.parse_literals(REGISTRY):
            lit.text.decode("ascii")

    def testParse_duplicateName_raises(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write('RASP_LITERAL(A, "x")\nRASP_LITERAL(A, "y")\n')
            path = f.name
        with self.assertRaises(ValueError):
            literals.parse_literals(path)

    def testParse_emptyText_raises(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write('RASP_LITERAL(A, "")\n')
            path = f.name
        with self.assertRaises(ValueError):
            literals.parse_literals(path)

    def testParse_ignoresCommentsAndBlankLines(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write('/* header */\n\nRASP_LITERAL(A, "x")  /* trailing */\n')
            path = f.name
        self.assertEqual(literals.parse_literals(path), [literals.Literal(name="A", raw="x", text=b"x")])

    def testParse_wrongShape_raises(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write("RASP_LITERAL(A, 'x')\n")
            path = f.name
        with self.assertRaises(ValueError):
            literals.parse_literals(path)


class StrictRegistryTest(unittest.TestCase):
    def testUnescape_nonAsciiOrControl_rejected(self) -> None:
        for raw in ["é", "a\x00b", "a\nb"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                literals.unescape_c(raw)

    def testParser_commentTokensInsideQuotes_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "literals.def"
            path.write_text('/* multi\nline */ RASP_LITERAL(URL, "https://host/a/*b*/") // tail\n')
            self.assertEqual(literals.parse_literals(path)[0].text, b"https://host/a/*b*/")

    def testParser_oversize_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "literals.def"
            path.write_text('RASP_LITERAL(BIG, "' + "a" * 257 + '")')
            with self.assertRaises(ValueError):
                literals.parse_literals(path)
