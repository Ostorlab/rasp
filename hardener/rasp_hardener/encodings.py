"""Seeded invertible affine byte encodings, absorbed into AES lookup tables.

These are byte-local GF(2) mixing bijections, not the complete Chow nonlinear
encoded-XOR construction and not evidence of resistance to DCA or DFA.
"""
from __future__ import annotations

import hashlib
import hmac


def byte_encoding(seed: bytes, boundary: int, position: int) -> tuple[list[int], list[int], int]:
    """Return linear map, affine inverse, and offset for one AES state byte."""
    if len(seed) != 32:
        raise ValueError("encoding seed must be 32 bytes")
    material = b"".join(hmac.new(seed, b"rasp/aes-encoding/v1" + bytes([boundary, position, counter]), hashlib.sha256).digest() for counter in range(5))
    basis = [1 << bit for bit in range(8)]
    # Elementary column additions preserve rank; swaps add more seed diversity.
    for index in range(0, 128, 2):
        left, right = material[index] % 8, material[index + 1] % 8
        if left != right:
            basis[left] ^= basis[right]
    linear = []
    for value in range(256):
        mapped = 0
        for bit in range(8):
            if value & (1 << bit) != 0:
                mapped ^= basis[bit]
        linear.append(mapped)
    offset = material[128]
    inverse = [0] * 256
    for value, mapped in enumerate(linear):
        inverse[mapped ^ offset] = value
    return linear, inverse, offset
