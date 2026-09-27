"""Reference AES-128 against the FIPS-197 known-answer vectors."""

import unittest

from rasp_hardener import aes


class AesTest(unittest.TestCase):
    def test_fips197_c1_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(aes.encrypt_block_key(key, pt).hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_fips197_appendixb_vector(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        self.assertEqual(aes.encrypt_block_key(key, pt).hex(), "3925841d02dc09fbdc118597196a0b32")

    def test_key_expansion_shape(self):
        rks = aes.key_expansion(bytes(16))
        self.assertEqual(len(rks), 11)
        self.assertTrue(all(len(rk) == 16 for rk in rks))

    def test_shift_rows_is_a_permutation(self):
        state = list(range(16))
        shifted = aes.shift_rows(state)
        self.assertEqual(sorted(shifted), list(range(16)))
        # Row 0 unchanged (shift 0); index 0 stays.
        self.assertEqual(shifted[0], 0)

    def test_bad_key_length(self):
        with self.assertRaises(ValueError):
            aes.key_expansion(bytes(15))

    def test_gf_mul_known(self):
        # 0x57 · 0x13 = 0xfe (FIPS-197 §4.2 example).
        self.assertEqual(aes.gf_mul(0x57, 0x13), 0xFE)


if __name__ == "__main__":
    unittest.main()
