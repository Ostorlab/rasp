"""Known-answer tests for the trusted AES generation primitives."""

from __future__ import annotations

import pytest

from rasp_whitebox import aes


def testExpandKey_whenFipsKey_matchesPublishedSchedule() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    expected = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "d6aa74fdd2af72fadaa678f1d6ab76fe"
        "b692cf0b643dbdf1be9bc5006830b3fe"
        "b6ff744ed2c2c9bf6c590cbf0469bf41"
        "47f7f7bc95353e03f96c32bcfd058dfd"
        "3caaa3e8a99f9deb50f3af57adf622aa"
        "5e390f7df7a69296a7553dc10aa31f6b"
        "14f9701ae35fe28c440adf4d4ea9c026"
        "47438735a41c65b9e016baf4aebf7ad2"
        "549932d1f08557681093ed9cbe2c974e"
        "13111d7fe3944a17f307a78b4d2b30c5"
    )
    assert b"".join(aes.expand_key(key)) == expected


@pytest.mark.parametrize("length", [0, 15, 17, 24, 32])
def testExpandKey_whenInvalidKeyLength_rejectsInput(length: int) -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        aes.expand_key(bytes(length))


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [(0x57, 0x13, 0xFE), (0x57, 0x83, 0xC1), (0x80, 2, 0x1B), (0, 255, 0)],
)
def testMultiply_whenKnownFieldProduct_matchesAesField(
    left: int, right: int, expected: int
) -> None:
    assert aes.multiply(left, right) == expected


def testSbox_whenEnumerated_isStandardPermutation() -> None:
    assert len(aes.SBOX) == 256
    assert set(aes.SBOX) == set(range(256))
    assert aes.SBOX[:16].hex() == "637c777bf26b6fc53001672bfed7ab76"
    assert aes.SBOX[0x53] == 0xED
