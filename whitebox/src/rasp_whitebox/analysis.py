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


def xor_key_candidates(final_table: bytes, xor_table: bytes) -> tuple[int, ...]:
    """Reproduce the adaptive attack on a final table and its feeding XOR table.

    Correct inverse-S-box guesses restore the rectangle identity
    Y(a,b) XOR Y(a,0) XOR Y(0,b) XOR Y(0,0) == 0.
    This exposes the known failure of arbitrary byte encodings too.
    """
    if len(final_table) != 256 or len(set(final_table)) != 256:
        raise ValueError("final table must be a permutation of 256 bytes")
    if len(xor_table) != 65536:
        raise ValueError("XOR table must contain 65536 bytes")
    candidates = []
    for key_byte in range(256):
        decoded = bytes(_INVERSE_SBOX[value ^ key_byte] for value in final_table)
        origin = decoded[xor_table[0]]
        if all(
            decoded[xor_table[(left << 8) | right]]
            == decoded[xor_table[left << 8]] ^ decoded[xor_table[right]] ^ origin
            for left in range(1, 256)
            for right in range(1, 256)
        ):
            candidates.append(key_byte)
    return tuple(candidates)
