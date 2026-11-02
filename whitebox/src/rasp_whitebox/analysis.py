"""Reproduce the final-table nibble-separability attack, without key logging."""

from rasp_whitebox import aes

_INVERSE_SBOX = bytes(aes.SBOX.index(value) for value in range(256))


def final_key_candidates(table: bytes) -> tuple[int, ...]:
    """Find final-round key bytes whose inverse S-box restores nibble separation.

    This is the DeepSeek attack predicate, independent of binary layout. Empty
    results only reject this predicate; they do not establish white-box security.
    """
    if len(table) != 256 or len(set(table)) != 256:
        raise ValueError("final table must be a permutation of 256 bytes")
    candidates = []
    for key_byte in range(256):
        decoded = bytes(_INVERSE_SBOX[value ^ key_byte] for value in table)
        high = [decoded[value << 4] >> 4 for value in range(16)]
        low = [decoded[value] & 15 for value in range(16)]
        if len(set(high)) != 16 or len(set(low)) != 16:
            continue
        if all(
            decoded[value] == (high[value >> 4] << 4) | low[value & 15]
            for value in range(256)
        ):
            candidates.append(key_byte)
    return tuple(candidates)
