"""Direct contracts for seeded affine GF(2) byte encodings."""
from __future__ import annotations

import unittest

from rasp_hardener import encodings

SEED = bytes(range(32))


class ByteEncodingTest(unittest.TestCase):
    def testByteEncoding_withValidSeed_returns256EntryBijections(self) -> None:
        linear, inverse, offset = encodings.byte_encoding(SEED, 0, 0)
        self.assertEqual(len(linear), 256)
        self.assertEqual(len(inverse), 256)
        self.assertEqual(sorted(linear), list(range(256)))
        self.assertEqual(sorted(inverse), list(range(256)))
        self.assertGreaterEqual(offset, 0)
        self.assertLess(offset, 256)
        self.assertEqual(linear[0], 0)
        for value in range(256):
            for bit in range(8):
                self.assertEqual(linear[value ^ (1 << bit)], linear[value] ^ linear[1 << bit])

    def testByteEncoding_forEveryByte_affineInverseRestoresInput(self) -> None:
        for boundary, position in [(0, 0), (4, 7), (8, 15)]:
            linear, inverse, offset = encodings.byte_encoding(SEED, boundary, position)
            for value in range(256):
                with self.subTest(boundary=boundary, position=position, value=value):
                    self.assertEqual(inverse[linear[value] ^ offset], value)

    def testByteEncoding_withSameParameters_isDeterministic(self) -> None:
        self.assertEqual(encodings.byte_encoding(SEED, 0, 0), encodings.byte_encoding(SEED, 0, 0))

    def testByteEncoding_withDifferentSeed_changesEncoding(self) -> None:
        self.assertNotEqual(encodings.byte_encoding(SEED, 0, 0), encodings.byte_encoding(bytes(reversed(SEED)), 0, 0))

    def testByteEncoding_withDifferentBoundary_changesEncoding(self) -> None:
        self.assertNotEqual(encodings.byte_encoding(SEED, 0, 0), encodings.byte_encoding(SEED, 1, 0))

    def testByteEncoding_withDifferentPosition_changesEncoding(self) -> None:
        self.assertNotEqual(encodings.byte_encoding(SEED, 0, 0), encodings.byte_encoding(SEED, 0, 1))

    def testByteEncoding_withSeedNotExactly32Bytes_raisesValueError(self) -> None:
        for length in [0, 1, 16, 31, 33, 64]:
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "^encoding seed must be 32 bytes$"):
                    encodings.byte_encoding(bytes(length), 0, 0)


if __name__ == "__main__":
    unittest.main()
