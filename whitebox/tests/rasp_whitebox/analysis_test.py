"""Positive controls for the observed attack, including all final key bytes."""

import pytest

from rasp_whitebox import aes
from rasp_whitebox import analysis


@pytest.mark.parametrize("key_byte", range(256))
def testFinalKeyCandidates_whenLegacyEncoding_recoversKeyByte(key_byte: int) -> None:
    # Two independent nontrivial nibble permutations, plus the penultimate key.
    low = bytes((index * 5 + 7) % 16 for index in range(16))
    high = bytes((index * 11 + 3) % 16 for index in range(16))
    table = bytes(
        aes.SBOX[((high[value >> 4] << 4) | low[value & 15]) ^ 0xA7] ^ key_byte
        for value in range(256)
    )
    assert analysis.final_key_candidates(table) == (key_byte,)


@pytest.mark.parametrize("table", [b"", bytes(256), bytes(255)])
def testFinalKeyCandidates_whenInvalidTable_rejectsInput(table: bytes) -> None:
    with pytest.raises(ValueError, match="permutation"):
        analysis.final_key_candidates(table)
