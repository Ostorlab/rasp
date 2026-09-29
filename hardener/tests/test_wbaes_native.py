"""Cross-language check: the native white-box evaluator agrees with the Python reference.

Emits the white-box table header for a fixed key, compiles a C harness against the real ``wbaes.c`` /
``securestore.c`` / ``sha256.c``, and asserts the C block encryption, CTR keystream and SecureStore seal/open
all match the Python reference (which itself matches FIPS-197). Mirrors verifier/tests/test_native_seal.py.
Skipped when a C compiler or the native sources are unavailable.
"""

import binascii
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import aes, whitebox

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wbaes_tables.h"
#include "wbaes.h"
#include "securestore.h"

static void put_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static size_t get_hex(const char *h, uint8_t *out) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        char c[3] = {h[i * 2], h[i * 2 + 1], 0};
        out[i] = (uint8_t)strtol(c, NULL, 16);
    }
    return n;
}

int main(int argc, char **argv) {
    const uint32_t *t2 = &RASP_WBAES_TYPE2[0][0][0];
    const uint8_t *last = &RASP_WBAES_LAST[0][0];

    if (argc >= 3 && strcmp(argv[1], "block") == 0) {
        uint8_t in[16], out[16];
        get_hex(argv[2], in);
        rasp_wbaes_encrypt_block(t2, last, in, out);
        put_hex(out, 16);
    } else if (argc >= 3 && strcmp(argv[1], "cmac") == 0) {
        uint8_t msg[8192], tag[16];
        size_t n = get_hex(argv[2], msg);
        rasp_wbaes_cmac(t2, last, msg, n, tag);
        put_hex(tag, 16);
    } else if (argc >= 4 && strcmp(argv[1], "seal") == 0) {
        uint8_t nonce[12], plain[4096], out[4096 + 28];
        get_hex(argv[2], nonce);
        size_t n = get_hex(argv[3], plain);
        int m = rasp_secure_store_seal(t2, last, nonce, plain, n, out);
        put_hex(out, (size_t)m);
    } else if (argc >= 3 && strcmp(argv[1], "open") == 0) {
        uint8_t sealed[4096 + 28], out[4096];
        size_t n = get_hex(argv[2], sealed);
        int m = rasp_secure_store_open(t2, last, sealed, n, out);
        if (m < 0) { printf("ERR\n"); return 0; }
        put_hex(out, (size_t)m);
    }
    return 0;
}
"""


@unittest.skipUnless(shutil.which("cc") or shutil.which("gcc"), "no C compiler")
@unittest.skipUnless(CPP.is_dir(), "native sources not present")
class WbAesInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.tables = whitebox.generate(KEY, encoding_seed=b"e" * 32)
        (cls.tmp / "wbaes_tables.h").write_text(whitebox.render_tables_h(cls.tables))
        harness = cls.tmp / "harness.c"
        harness.write_text(HARNESS)
        cls.binary = cls.tmp / "harness"
        compiler = shutil.which("cc") or shutil.which("gcc")
        subprocess.run(
            [compiler, "-O2", "-I", str(cls.tmp), "-I", str(CPP), str(harness),
             str(CPP / "wbaes.c"), str(CPP / "securestore.c"), "-o", str(cls.binary)],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_harness(self, *args):
        result = subprocess.run([str(self.binary), *args], check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def test_native_block_matches_reference(self):
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        out = self.run_harness("block", pt.hex())
        self.assertEqual(out, "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(out, self.tables.encrypt_block(pt).hex())

    def test_native_block_matches_on_random(self):
        for _ in range(20):
            pt = os.urandom(16)
            self.assertEqual(self.run_harness("block", pt.hex()), self.tables.encrypt_block(pt).hex())

    def test_native_cmac_matches_python(self):
        for length in (0, 1, 16, 20, 32, 100):
            msg = os.urandom(length)
            self.assertEqual(self.run_harness("cmac", msg.hex()), whitebox.cmac(self.tables, msg).hex())

    def test_native_secure_store_matches_python(self):
        for length in (0, 1, 16, 33, 100):
            nonce = os.urandom(12)
            plain = os.urandom(length)
            c_sealed = self.run_harness("seal", nonce.hex(), plain.hex())
            py_sealed = whitebox.secure_store_seal(self.tables, nonce, plain)
            self.assertEqual(c_sealed, py_sealed.hex())
            # nonce(12) + ciphertext(length) + tag(16)
            self.assertEqual(len(py_sealed), length + 28)
            # And the C side opens the Python-sealed blob back to the plaintext.
            opened = self.run_harness("open", py_sealed.hex())
            self.assertEqual(opened, plain.hex())

    def test_native_opens_python_seal(self):
        nonce = os.urandom(12)
        plain = b"transfer:1000:IBAN"
        py_sealed = whitebox.secure_store_seal(self.tables, nonce, plain)
        opened = self.run_harness("open", binascii.hexlify(py_sealed).decode())
        self.assertEqual(opened, plain.hex())

    def test_native_open_rejects_tamper(self):
        nonce = os.urandom(12)
        sealed = bytearray(whitebox.secure_store_seal(self.tables, nonce, b"sensitive-value"))
        sealed[13] ^= 0x01  # flip a ciphertext byte
        self.assertEqual(self.run_harness("open", bytes(sealed).hex()), "ERR")
        # Flipping a tag byte is also rejected.
        sealed2 = bytearray(whitebox.secure_store_seal(self.tables, nonce, b"sensitive-value"))
        sealed2[-1] ^= 0x01
        self.assertEqual(self.run_harness("open", bytes(sealed2).hex()), "ERR")


if __name__ == "__main__":
    unittest.main()
