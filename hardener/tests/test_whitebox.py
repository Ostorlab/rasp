"""White-box AES-128: correctness vs reference, CTR round trip, SecureStore, and header rendering."""

import os
import unittest

from rasp_hardener import aes, whitebox

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PT = bytes.fromhex("00112233445566778899aabbccddeeff")
CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


class WhiteBoxTest(unittest.TestCase):
    def setUp(self):
        self.tables = whitebox.generate(KEY)

    def test_matches_fips_vector(self):
        self.assertEqual(self.tables.encrypt_block(PT), CT)

    def test_matches_reference_on_random_blocks(self):
        # Reuse one key's tables across many blocks (table generation is the expensive part).
        rks = aes.key_expansion(KEY)
        for _ in range(200):
            block = os.urandom(16)
            self.assertEqual(self.tables.encrypt_block(block), aes.encrypt_block(rks, block))

    def test_matches_reference_on_random_keys(self):
        for _ in range(10):
            key = os.urandom(16)
            block = os.urandom(16)
            self.assertEqual(
                whitebox.generate(key).encrypt_block(block), aes.encrypt_block_key(key, block)
            )

    def test_block_must_be_16_bytes(self):
        with self.assertRaises(ValueError):
            self.tables.encrypt_block(b"short")

    def test_ctr_round_trip(self):
        nonce = os.urandom(12)
        for length in (0, 1, 15, 16, 17, 64, 100):
            data = os.urandom(length)
            enc = whitebox.ctr(self.tables, nonce, data)
            self.assertEqual(len(enc), length)
            self.assertEqual(whitebox.ctr(self.tables, nonce, enc), data)

    def test_ctr_matches_openssl_style_keystream(self):
        # CTR with all-zero nonce: ciphertext of zeros is the keystream = E(counter blocks).
        nonce = bytes(12)
        keystream = whitebox.ctr(self.tables, nonce, bytes(32))
        block0 = aes.encrypt_block_key(KEY, bytes(12) + (0).to_bytes(4, "big"))
        block1 = aes.encrypt_block_key(KEY, bytes(12) + (1).to_bytes(4, "big"))
        self.assertEqual(keystream, block0 + block1)

    def test_cmac_rfc4493_vectors(self):
        # Authoritative AES-CMAC vectors from RFC 4493 (key 2b7e1516...).
        tables = whitebox.generate(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
        msg = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        )
        expected = {
            0: "bb1d6929e95937287fa37d129b756746",
            16: "070a16b46b4d4144f79bdd9dd04a287c",
            40: "dfa66747de9ae63030ca32611497c827",
            64: "51f0bebf7e3b9d92fc49741779363cfe",
        }
        for length, want in expected.items():
            self.assertEqual(whitebox.cmac(tables, msg[:length]).hex(), want)

    def test_secure_store_seal_open(self):
        nonce = os.urandom(12)
        plain = b"account balance: 42.00 EUR"
        sealed = whitebox.secure_store_seal(self.tables, nonce, plain)
        self.assertEqual(len(sealed), len(plain) + whitebox.NONCE_LEN + whitebox.TAG_LEN)
        self.assertNotIn(plain, sealed)  # ciphertext, not cleartext
        self.assertEqual(whitebox.secure_store_open(self.tables, sealed), plain)

    def test_secure_store_rejects_tamper(self):
        nonce = os.urandom(12)
        sealed = bytearray(whitebox.secure_store_seal(self.tables, nonce, b"sensitive-value"))
        sealed[13] ^= 0x01  # flip a ciphertext byte
        with self.assertRaises(ValueError):
            whitebox.secure_store_open(self.tables, bytes(sealed))
        sealed2 = bytearray(whitebox.secure_store_seal(self.tables, nonce, b"sensitive-value"))
        sealed2[-1] ^= 0x01  # flip a tag byte
        with self.assertRaises(ValueError):
            whitebox.secure_store_open(self.tables, bytes(sealed2))

    def test_secure_store_open_too_short(self):
        with self.assertRaises(ValueError):
            whitebox.secure_store_open(self.tables, b"tiny")

    def test_render_tables_h_shape(self):
        header = whitebox.render_tables_h(self.tables)
        self.assertIn("RASP_WBAES_TYPE2[9][16][256]", header)
        self.assertIn("RASP_WBAES_LAST[16][256]", header)
        self.assertNotIn(KEY.hex(), header)  # the key is not a literal in the output

    def test_nonce_length_validated(self):
        with self.assertRaises(ValueError):
            whitebox.ctr(self.tables, b"short", b"data")


if __name__ == "__main__":
    unittest.main()


class EncodedTablesTest(unittest.TestCase):
    def testEncodedTables_knownAndVariedBlocks_matchAes(self) -> None:
        key = bytes(range(16))
        first = whitebox.generate(key, encoding_seed=b"a" * 32)
        second = whitebox.generate(key, encoding_seed=b"b" * 32)
        self.assertNotEqual(first.type2, second.type2)
        self.assertEqual(first.type2, whitebox.generate(key, encoding_seed=b"a" * 32).type2)
        for counter in range(32):
            block = bytes((position * 19 + counter * 7) % 256 for position in range(16))
            self.assertEqual(first.encrypt_block(block), aes.encrypt_block_key(key, block))
            self.assertEqual(second.encrypt_block(block), aes.encrypt_block_key(key, block))

    def testEncodedTables_invalidSeed_rejected(self) -> None:
        with self.assertRaises(ValueError):
            whitebox.generate(bytes(16), encoding_seed=b"short")
