"""ELF64 section reader: section discovery, integrity-region selection, and input validation."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import elf

LIB_SRC = """
static const char ro[] = "read-only-constant-marker";
int f(int a){ return a + (int)ro[0]; }
int g(int a){ return a * 3; }
"""


@unittest.skipUnless(shutil.which("cc") or shutil.which("gcc"), "no C compiler")
class ElfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        src = cls.tmp / "lib.c"
        src.write_text(LIB_SRC)
        cls.lib = cls.tmp / "lib.so"
        compiler = shutil.which("cc") or shutil.which("gcc")
        subprocess.run([compiler, "-shared", "-fPIC", "-O2", str(src), "-o", str(cls.lib)],
                       check=True, capture_output=True)
        cls.data = cls.lib.read_bytes()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_finds_text_section(self):
        names = {s.name for s in elf.read_sections(self.data)}
        self.assertIn(".text", names)

    def test_integrity_sections_are_nonwritable_progbits_sorted(self):
        secs = elf.integrity_sections(self.data)
        self.assertGreater(len(secs), 0)
        self.assertTrue(any(s.name == ".text" for s in secs))
        offsets = [s.offset for s in secs]
        self.assertEqual(offsets, sorted(offsets))
        for s in secs:
            self.assertEqual(s.type, elf.SHT_PROGBITS)
            self.assertTrue(s.flags & elf.SHF_ALLOC)
            self.assertFalse(s.flags & elf.SHF_WRITE)
            self.assertGreater(s.size, 0)

    def test_writable_sections_excluded(self):
        integrity = {s.name for s in elf.integrity_sections(self.data)}
        # .data/.got are writable and must not be part of the integrity root.
        self.assertNotIn(".data", integrity)
        self.assertNotIn(".got", integrity)

    def test_rejects_non_elf(self):
        with self.assertRaises(elf.ElfError):
            elf.read_sections(b"not an elf file" + b"\x00" * 64)

    def test_rejects_32bit(self):
        data = bytearray(self.data)
        data[4] = 1  # ELFCLASS32
        with self.assertRaises(elf.ElfError):
            elf.read_sections(bytes(data))


if __name__ == "__main__":
    unittest.main()
