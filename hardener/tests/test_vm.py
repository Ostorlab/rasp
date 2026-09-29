"""Cross-language arithmetic VM contract, including rejection before output."""
from __future__ import annotations

import ctypes
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import seed
from rasp_hardener import vm

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp/android/src/main/cpp"


@unittest.skipUnless(shutil.which("cc"), "C compiler required")
class VmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        library = pathlib.Path(cls.directory.name) / "vm.so"
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(CPP / "vm.c"), "-o", str(library)], check=True)
        cls.library = ctypes.CDLL(str(library))
        cls.native = cls.library.rasp_vm_run
        cls.native.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        cls.native.restype = ctypes.c_int
        cls.profile = seed.BuildProfile.derive(bytes(range(16)))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def testExpression_wrappingAndSeededOpcodes_matchC(self) -> None:
        expression = "((r0 + 4294967295) ^ r1) + (r2 << r3)"
        code = vm.compile_expression(expression, self.profile)
        other = seed.BuildProfile.derive(bytes(reversed(range(16))))
        self.assertNotEqual(code, vm.compile_expression(expression, other))
        for value in range(100):
            inputs = [value * 912347, value + 15, value * 3742, value, 0, 0, 0, 0]
            expected = ((((inputs[0] - 1) & 0xFFFFFFFF) ^ inputs[1]) + ((inputs[2] << (inputs[3] & 31)) & 0xFFFFFFFF)) & 0xFFFFFFFF
            self.assertEqual(vm.execute(code, vm.opcode_bytes(self.profile), inputs), expected)
            result = ctypes.c_uint32(0)
            self.assertEqual(self.native(code, len(code), vm.opcode_bytes(self.profile), (ctypes.c_uint32 * 8)(*inputs), 1000, ctypes.byref(result)), 0)
            self.assertEqual(result.value, expected)

    def testInvalidPrograms_andBudget_rejectedWithOutputUntouched(self) -> None:
        loop = vm.assemble([vm.Instruction("JMP", 0, immediate=0)], self.profile)
        valid = vm.compile_expression("r0 + r1", self.profile)
        malformed = [b"", valid[:-1], bytes([255]) + valid[1:], valid[:1] + bytes([9]) + valid[2:], loop]
        for code in malformed:
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    vm.execute(code, vm.opcode_bytes(self.profile), [1] * 8, 10)
                result = ctypes.c_uint32(0x12345678)
                self.assertEqual(self.native(code, len(code), vm.opcode_bytes(self.profile), (ctypes.c_uint32 * 8)(*[1] * 8), 10, ctypes.byref(result)), -1)
                self.assertEqual(result.value, 0x12345678)
        for expression in ["__import__('os')", "r4", "r0 / r1", "r0 ** 2"]:
            with self.assertRaises(ValueError):
                vm.compile_expression(expression, self.profile)
