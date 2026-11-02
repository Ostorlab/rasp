"""Compile a classic encoded-table AES-128 research baseline.

The format is deliberately public and has no white-box resistance claim. The
seed controls reproducible diversity, not security against structural attacks.
Only this trusted host code sees the key, round keys, and encoding inverses.

The 372736-byte blob has three contiguous regions, with no header or padding:
* T: [9 rounds][4 columns][4 input rows][256 inputs], little-endian uint32.
* XOR: [9 rounds][4 columns][3 layers][8 nibbles][256 input pairs], uint8.
* Final: [16 destination bytes][256 inputs], uint8.

Words place output row zero in the least significant byte. Nibbles count from
the least significant nibble. XOR pair indices are (left << 4) | right. Layers
zero and one join T rows (0, 1) and (2, 3); layer two joins those two results.
T and final table indices use destination positions after ShiftRows.
"""

from __future__ import annotations

import collections.abc
import hashlib
import importlib.resources

from rasp_whitebox import aes

T_OFFSET = 0
XOR_OFFSET = 9 * 16 * 256 * 4
FINAL_OFFSET = XOR_OFFSET + 9 * 4 * 3 * 8 * 256
TABLE_SIZE = FINAL_OFFSET + 16 * 256

_MIX_COLUMNS = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


class Error(ValueError):
    """Invalid compiler input or serialized table data."""


def _random_bytes(seed: bytes) -> collections.abc.Iterator[int]:
    """Expand a seed with domain-separated SHAKE256 counter blocks."""
    counter = 0
    while True:
        yield from hashlib.shake_256(
            b"RASP-WB-ENCODINGS-v1\x00" + seed + counter.to_bytes(8, "big")
        ).digest(4096)
        counter += 1


def _permutation(randomness: collections.abc.Iterator[int]) -> bytes:
    """Draw a uniform nibble permutation using rejection and Fisher-Yates."""
    values = list(range(16))
    for index in range(15, 0, -1):
        bound = index + 1
        limit = 256 - 256 % bound
        choice = next(randomness)
        while choice >= limit:
            choice = next(randomness)
        other = choice % bound
        values[index], values[other] = values[other], values[index]
    return bytes(values)


def _inverse(permutation: bytes) -> bytes:
    """Invert an encoding only on the trusted generation host."""
    result = bytearray(len(permutation))
    for value, encoded in enumerate(permutation):
        result[encoded] = value
    return bytes(result)


def _word_encoding(randomness: collections.abc.Iterator[int]) -> tuple[bytes, ...]:
    """Give each nibble of a contribution its own independent permutation."""
    return tuple(_permutation(randomness) for _ in range(8))


def _tbox(
    key_byte: int,
    decoding: bytes,
    input_row: int,
    encoding: tuple[bytes, ...],
) -> bytes:
    """Fuse input decoding, key addition, SubBytes, and one MixColumns input."""
    table = bytearray()
    for decoded in decoding:
        substituted = aes.SBOX[decoded ^ key_byte]
        contribution = sum(
            aes.multiply(substituted, _MIX_COLUMNS[row][input_row]) << (8 * row)
            for row in range(4)
        )
        encoded = sum(
            permutation[(contribution >> (4 * nibble)) & 15] << (4 * nibble)
            for nibble, permutation in enumerate(encoding)
        )
        table.extend(encoded.to_bytes(4, "little"))
    return bytes(table)


def _xor_tables(
    left_encoding: tuple[bytes, ...],
    right_encoding: tuple[bytes, ...],
    output_encoding: tuple[bytes, ...],
) -> bytes:
    """Join encoded words without materializing decoded values at runtime."""
    tables = bytearray()
    for left, right, output in zip(
        left_encoding, right_encoding, output_encoding, strict=True
    ):
        left_inverse = _inverse(left)
        right_inverse = _inverse(right)
        tables.extend(
            output[left_inverse[first] ^ right_inverse[second]]
            for first in range(16)
            for second in range(16)
        )
    return bytes(tables)


def _byte_decoding(low: bytes, high: bytes) -> bytes:
    """Translate two output-nibble encodings to the next input-byte inverse."""
    low_inverse = _inverse(low)
    high_inverse = _inverse(high)
    return bytes(
        low_inverse[value & 15] | (high_inverse[value >> 4] << 4)
        for value in range(256)
    )


def generate(key: bytes, seed: bytes) -> bytes:
    """Specialize AES-128 into a reproducible encoded lookup-table network."""
    if len(key) != 16:
        raise Error("AES-128 key must be 16 bytes")
    if len(seed) != 32:
        raise Error("encoding seed must be 32 bytes")
    round_keys = aes.expand_key(key)
    randomness = _random_bytes(seed)
    input_decodings = [bytes(range(256)) for _ in range(16)]
    tboxes = bytearray()
    xor_tables = bytearray()
    for round_index in range(9):
        next_decodings = [b""] * 16
        for column in range(4):
            contributions = tuple(_word_encoding(randomness) for _ in range(4))
            joins = tuple(_word_encoding(randomness) for _ in range(3))
            for row in range(4):
                source = 4 * ((column + row) % 4) + row
                tboxes.extend(
                    _tbox(
                        round_keys[round_index][source],
                        input_decodings[source],
                        row,
                        contributions[row],
                    )
                )
            xor_tables.extend(_xor_tables(contributions[0], contributions[1], joins[0]))
            xor_tables.extend(_xor_tables(contributions[2], contributions[3], joins[1]))
            xor_tables.extend(_xor_tables(joins[0], joins[1], joins[2]))
            for row in range(4):
                next_decodings[4 * column + row] = _byte_decoding(
                    joins[2][2 * row], joins[2][2 * row + 1]
                )
        input_decodings = next_decodings
    final_tables = bytearray()
    for destination in range(16):
        row = destination % 4
        source = 4 * ((destination // 4 + row) % 4) + row
        final_tables.extend(
            aes.SBOX[decoded ^ round_keys[9][source]] ^ round_keys[10][destination]
            for decoded in input_decodings[source]
        )
    return bytes(tboxes + xor_tables + final_tables)


def emit_header(table_data: bytes) -> str:
    """Render a self-contained C++20 encrypt_block header without a key API."""
    if len(table_data) != TABLE_SIZE:
        raise Error(f"table data must contain exactly {TABLE_SIZE} bytes")
    template = (
        importlib.resources.files("rasp_whitebox")
        .joinpath("native", "aes.h.in")
        .read_text(encoding="utf-8")
    )
    initializer = "\n".join(
        "    "
        + ", ".join(f"0x{value:02x}" for value in table_data[offset : offset + 16])
        + ","
        for offset in range(0, len(table_data), 16)
    )
    return template.replace("@TABLE_DATA@", initializer)
