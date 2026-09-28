"""Measured fault model: 32 exercised first-round table corruptions, one evaluator only."""
from __future__ import annotations

import ctypes
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import aes
from rasp_hardener import whitebox

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp/android/src/main/cpp"


@unittest.skipUnless(shutil.which("cc"), "C compiler required")
class RedundantAesTest(unittest.TestCase):
    def testCheckedAes_singleExercisedTableFaults_detects32of32(self) -> None:
        key = bytes(range(16))
        block = bytes(range(16))
        first = whitebox.generate(key, encoding_seed=b"a" * 32)
        second = whitebox.generate(key, encoding_seed=b"b" * 32)
        expected = aes.encrypt_block_key(key, block)
        self.assertEqual(first.encrypt_block_checked(second, block), expected)
        with tempfile.TemporaryDirectory() as directory:
            library = pathlib.Path(directory) / "checked.so"
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(CPP / "wbaes.c"), "-o", str(library)], check=True)
            checked = ctypes.CDLL(str(library)).rasp_wbaes_encrypt_block_checked
            checked.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
            checked.restype = ctypes.c_int
            flatten = lambda tables: [entry for row in tables.type2 for column in row for entry in column]
            a = (ctypes.c_uint32 * (9 * 16 * 256))(*flatten(first))
            b = (ctypes.c_uint32 * (9 * 16 * 256))(*flatten(second))
            last_a = bytes(entry for column in first.last for entry in column)
            last_b = bytes(entry for column in second.last for entry in column)
            output = ctypes.create_string_buffer(16)
            self.assertEqual(checked(a, last_a, b, last_b, block, output), 0)
            self.assertEqual(output.raw, expected)
            shifted = aes.shift_rows(list(block))
            detected = 0
            for trial in range(32):
                position = trial % 16
                index = position * 256 + shifted[position]
                mask = 1 << trial
                a[index] ^= mask
                first.type2[0][position][shifted[position]] ^= mask
                ctypes.memset(output, 0xAA, 16)
                self.assertEqual(checked(a, last_a, b, last_b, block, output), -1)
                self.assertEqual(output.raw, b"\xAA" * 16)
                with self.assertRaises(ValueError):
                    first.encrypt_block_checked(second, block)
                detected += 1
                a[index] ^= mask
                first.type2[0][position][shifted[position]] ^= mask
            self.assertEqual(detected, 32)
