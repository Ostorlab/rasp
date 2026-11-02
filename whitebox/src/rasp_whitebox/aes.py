"""AES-128 primitives used only on the trusted table-generation host."""

from __future__ import annotations

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)


class Error(ValueError):
    """Invalid input to the trusted AES generation primitives."""


def multiply(left: int, right: int) -> int:
    """Multiply two byte values in the AES field GF(2**8)."""
    product = 0
    while right > 0:
        if right & 1 == 1:
            product ^= left
        left = (left << 1) ^ (0x11B if left & 0x80 != 0 else 0)
        right >>= 1
    return product


def expand_key(key: bytes) -> tuple[bytes, ...]:
    """Return the eleven AES-128 round keys; never serialize these keys."""
    if len(key) != 16:
        raise Error("AES-128 key must be 16 bytes")
    expanded = bytearray(key)
    round_constant = 1
    while len(expanded) < 176:
        word = expanded[-4:]
        if len(expanded) % 16 == 0:
            word = bytearray(SBOX[value] for value in word[1:] + word[:1])
            word[0] ^= round_constant
            round_constant = multiply(round_constant, 2)
        for value in word:
            expanded.append(expanded[-16] ^ value)
    return tuple(bytes(expanded[offset : offset + 16]) for offset in range(0, 176, 16))
