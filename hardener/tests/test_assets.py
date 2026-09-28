"""Resource packages authenticate identity, live code root and ciphertext before open."""
from __future__ import annotations

import ctypes
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import assets
from rasp_hardener import guardmesh
from rasp_hardener import whitebox
from rasp_hardener import seed
from rasp_hardener import vm

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp/android/src/main/cpp"
KEY = bytes(range(32))
REGION = b"immutable code region fixture"
ROOT = guardmesh.guard_root([REGION])


class AssetTest(unittest.TestCase):
    def testPackage_wrongRootIdentityOrMutations_rejected(self) -> None:
        package = assets.seal(b"private bytecode", "rules.bin", KEY, ROOT, bytes(range(12)))
        self.assertEqual(assets.open_package(package, "rules.bin", KEY, ROOT), b"private bytecode")
        for identity, root in [("other.bin", ROOT), ("rules.bin", bytes(32))]:
            with self.assertRaises(ValueError):
                assets.open_package(package, identity, KEY, root)
        for offset in [0, 4, 16, 48, len(package) - 1]:
            mutated = bytearray(package)
            mutated[offset] ^= 1
            with self.assertRaises(ValueError):
                assets.open_package(bytes(mutated), "rules.bin", KEY, ROOT)
        with self.assertRaises(ValueError):
            assets.open_package(package[:-1], "rules.bin", KEY, ROOT)
        empty = assets.seal(b"", "empty", KEY, ROOT)
        self.assertEqual(assets.open_package(empty, "empty", KEY, ROOT), b"")

    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def testNativeOpen_liveRegionMutation_rejectedWithoutPlaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp = pathlib.Path(directory)
            (tmp / "tables.h").write_text(whitebox.render_tables_h(assets.tables(KEY, ROOT)))
            (tmp / "loader.c").write_text('''#include "assets.h"
#include "tables.h"
int open_asset(const unsigned char *region, size_t region_len, const unsigned char *package, size_t package_len, unsigned char *out) {
    unsigned char key[32]; for(int i=0;i<32;i++) key[i]=(unsigned char)i;
    rasp_region_t live={region,region_len};
    return rasp_asset_open(&RASP_WBAES_TYPE2[0][0][0], &RASP_WBAES_LAST[0][0], key, &live, 1, "rules.bin", package, package_len, out, 256);
}
int run_asset(const unsigned char *region, size_t region_len, const unsigned char *package, size_t package_len, unsigned *result) {
    unsigned char key[32]; for(int i=0;i<32;i++) key[i]=(unsigned char)i;
    rasp_region_t live={region,region_len}; unsigned inputs[8]={4,7,0,0,0,0,0,0};
    return rasp_asset_vm_run(&RASP_WBAES_TYPE2[0][0][0], &RASP_WBAES_LAST[0][0], key, &live, 1, "rules.bin", package, package_len, inputs, 100, result);
}''')
            library = tmp / "loader.so"
            subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-I", str(tmp), "-I", str(CPP), str(tmp / "loader.c")] + [str(CPP / name) for name in ["assets.c", "vm.c", "wbaes.c", "guard.c", "sha256.c", "literals.c", "strobf.c"]] + ["-o", str(library)], check=True)
            loaded = ctypes.CDLL(str(library))
            native = loaded.open_asset
            native.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            native.restype = ctypes.c_int
            package = assets.seal(b"secret", "rules.bin", KEY, ROOT)
            out = ctypes.create_string_buffer(256)
            self.assertEqual(native(REGION, len(REGION), package, len(package), out), 6)
            self.assertEqual(out.raw[:6], b"secret")
            for live, blob in [(b"changed code region", package), (REGION, package[:-1] + bytes([package[-1] ^ 1]))]:
                ctypes.memset(out, 0xAA, 256)
                self.assertEqual(native(live, len(live), blob, len(blob), out), -1)
                self.assertEqual(out.raw, b"\xAA" * 256)

            profile = seed.BuildProfile.derive(bytes(range(16)))
            program = vm.opcode_bytes(profile) + vm.compile_expression("(r0 + r1) ^ 123", profile)
            package = assets.seal(program, "rules.bin", KEY, ROOT)
            execute = loaded.run_asset
            execute.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint32)]
            execute.restype = ctypes.c_int
            result = ctypes.c_uint32(0)
            self.assertEqual(execute(REGION, len(REGION), package, len(package), ctypes.byref(result)), 0)
            self.assertEqual(result.value, (4 + 7) ^ 123)
            result.value = 12345
            self.assertEqual(execute(b"modified", 8, package, len(package), ctypes.byref(result)), -1)
            self.assertEqual(result.value, 12345)
