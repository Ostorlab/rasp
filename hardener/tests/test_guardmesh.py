"""Guard mesh: determinism, order/tamper sensitivity, offset derivation, key folding."""

import unittest

from rasp_hardener import guardmesh


class GuardMeshTest(unittest.TestCase):
    def test_known_answer(self):
        # Pinned so the C mesh (guard.c / native_test.c) can assert byte-for-byte agreement.
        regions = [b"", b"abc", bytes([0, 1, 2])]
        self.assertEqual(
            guardmesh.guard_root(regions).hex(),
            "42d544dbe00b9b6a4e567625542fc3b155a72f23a2b5e20d6308bf7690d0dc5f",
        )
        self.assertEqual(guardmesh.guard_offset(regions, 1000), 162)

    def test_deterministic(self):
        regions = [b"one", b"two"]
        self.assertEqual(guardmesh.guard_root(regions), guardmesh.guard_root(regions))

    def test_single_byte_tamper_changes_root_and_offset(self):
        base = [b"", b"abc", bytes([0, 1, 2])]
        tampered = [b"", b"abd", bytes([0, 1, 2])]
        self.assertNotEqual(guardmesh.guard_root(base), guardmesh.guard_root(tampered))
        self.assertNotEqual(
            guardmesh.guard_offset(base, 1000), guardmesh.guard_offset(tampered, 1000)
        )

    def test_order_sensitive(self):
        self.assertNotEqual(
            guardmesh.guard_root([b"a", b"b"]), guardmesh.guard_root([b"b", b"a"])
        )

    def test_offset_range(self):
        regions = [b"x" * 100]
        for modulus in (2, 7, 256, 100003):
            self.assertTrue(0 <= guardmesh.guard_offset(regions, modulus) < modulus)

    def test_offset_zero_modulus_rejected(self):
        with self.assertRaises(ValueError):
            guardmesh.guard_offset([b"x"], 0)

    def test_fold_key_depends_on_regions(self):
        key = b"\x11" * 32
        self.assertNotEqual(
            guardmesh.fold_key(key, [b"clean"]), guardmesh.fold_key(key, [b"tampered"])
        )
        self.assertEqual(len(guardmesh.fold_key(key, [b"clean"])), 32)

    def test_fold_key_known_answer(self):
        # Pinned so guard.c's rasp_guard_fold_key (native_test.c) can assert byte-for-byte agreement.
        base = bytes(range(32))
        regions = [b"", b"abc", bytes([0, 1, 2])]
        self.assertEqual(
            guardmesh.fold_key(base, regions).hex(),
            "4500af4d306867c320025903977d60ba0455aa1cd57c726fd8c10ad50f695cee",
        )


if __name__ == "__main__":
    unittest.main()
