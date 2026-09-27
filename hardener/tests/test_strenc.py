"""String/constant encryption: round trip, index sensitivity, and no cleartext leakage."""

import unittest

from rasp_hardener import strenc
from rasp_hardener.seed import SEED_LEN, BuildProfile


class StrEncTest(unittest.TestCase):
    def setUp(self):
        self.profile = BuildProfile.derive(bytes(range(SEED_LEN)))
        self.key = self.profile.string_key

    def test_round_trip(self):
        for idx, text in enumerate(["nativeScan", "dev/ostorlab/rasp", "()Ljava/lang/String;", "é—unicode"]):
            cipher = strenc.obfuscate(text, self.key, idx)
            self.assertEqual(strenc.deobfuscate(cipher, self.key, idx), text)

    def test_cipher_has_no_cleartext(self):
        text = "nativeSeal"
        cipher = strenc.obfuscate(text, self.key, 3)
        self.assertNotEqual(cipher, text.encode())
        # No 3-byte run of the plaintext survives in the ciphertext.
        for i in range(len(text) - 2):
            self.assertNotIn(text[i : i + 3].encode(), cipher)

    def test_same_text_different_index_differs(self):
        text = "nativeScan"
        self.assertNotEqual(
            strenc.obfuscate(text, self.key, 0), strenc.obfuscate(text, self.key, 1)
        )

    def test_repeated_chars_do_not_repeat_in_cipher(self):
        cipher = strenc.obfuscate("aaaaaaaa", self.key, 2)
        self.assertGreater(len(set(cipher)), 1)

    def test_encrypt_table_indexing(self):
        entries = {"A": "alpha", "B": "beta", "C": "gamma"}
        table = strenc.encrypt_table(entries, self.key)
        self.assertEqual([e.name for e in table], ["A", "B", "C"])
        for idx, e in enumerate(table):
            self.assertEqual(strenc.deobfuscate(e.cipher, self.key, idx), e.plaintext)

    def test_bad_key_length_rejected(self):
        with self.assertRaises(ValueError):
            strenc.obfuscate("x", b"short", 0)


if __name__ == "__main__":
    unittest.main()
