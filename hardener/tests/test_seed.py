"""Per-build polymorphism: determinism, independence, and diversity of the derived profile."""

import unittest

from rasp_hardener.seed import BASE_OPCODES, DETECTOR_IDS, SEED_LEN, BuildProfile, SeedError


class SeedTest(unittest.TestCase):
    def test_deterministic_from_seed(self):
        seed = bytes(range(SEED_LEN))
        a = BuildProfile.derive(seed)
        b = BuildProfile.derive(seed)
        self.assertEqual(a.build_id, b.build_id)
        self.assertEqual(a.build_key, b.build_key)
        self.assertEqual(a.string_key, b.string_key)
        self.assertEqual(a.opcode_map, b.opcode_map)
        self.assertEqual(a.detector_order, b.detector_order)

    def test_different_seeds_diverge(self):
        a = BuildProfile.derive(bytes(range(SEED_LEN)))
        b = BuildProfile.derive(bytes([1]) + bytes(range(1, SEED_LEN)))
        self.assertNotEqual(a.build_id, b.build_id)
        self.assertNotEqual(a.build_key, b.build_key)
        # A one-byte seed change should very likely permute opcodes and detectors differently.
        self.assertTrue(a.opcode_map != b.opcode_map or a.detector_order != b.detector_order)

    def test_outputs_are_independent(self):
        p = BuildProfile.derive(bytes(range(SEED_LEN)))
        # The public build_id must not reveal the secret build_key (distinct PRF labels).
        self.assertNotIn(p.build_id[2:], p.build_key_hex)
        self.assertNotEqual(p.build_key[:6].hex(), p.string_key[:6].hex())

    def test_build_key_and_string_key_length(self):
        p = BuildProfile.derive(bytes(range(SEED_LEN)))
        self.assertEqual(len(p.build_key), 32)
        self.assertEqual(len(p.string_key), 32)

    def test_opcode_map_is_a_permutation(self):
        p = BuildProfile.derive(bytes(range(SEED_LEN)))
        self.assertEqual(set(p.opcode_map.keys()), set(BASE_OPCODES))
        values = list(p.opcode_map.values())
        self.assertEqual(len(values), len(set(values)))  # distinct bytes
        self.assertTrue(all(0x10 <= v < 0x10 + len(BASE_OPCODES) for v in values))

    def test_detector_order_is_a_permutation(self):
        p = BuildProfile.derive(bytes(range(SEED_LEN)))
        self.assertEqual(set(p.detector_order), set(DETECTOR_IDS))
        self.assertEqual(len(p.detector_order), len(DETECTOR_IDS))

    def test_random_seed_when_none(self):
        a = BuildProfile.derive()
        b = BuildProfile.derive()
        self.assertNotEqual(a.seed, b.seed)

    def test_bad_seed_length_rejected(self):
        with self.assertRaises(SeedError):
            BuildProfile.derive(b"\x00" * 8)

    def test_summary_hides_secrets(self):
        p = BuildProfile.derive(bytes(range(SEED_LEN)))
        summary = p.summary()
        self.assertNotIn("build_key", summary)
        self.assertEqual(summary["build_id"], p.build_id)


if __name__ == "__main__":
    unittest.main()
