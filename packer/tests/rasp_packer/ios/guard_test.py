"""Tests for the at-rest guard: write_guard encrypts the marker into a runtime binary."""

import pathlib

from rasp_packer.ios import guard

_DATA = pathlib.Path(__file__).resolve().parent.parent / "data" / "runtime_config"
_BINARY = (_DATA / "RaspRuntime").read_bytes()


def testWriteGuard_whenBinaryHasNoGuardSection_returnsBinaryUnchanged() -> None:
    result = guard.write_guard(_BINARY)

    assert result == _BINARY


def testHashRegion_whenBytesDifferByOne_producesADifferentDigest() -> None:
    data_a = b"\x01\x02\x03\x04"
    data_b = b"\x01\x02\x03\x05"

    assert guard._hash_region(data_a) != guard._hash_region(data_b)


def testHashRegion_whenCalledTwice_producesTheSameDigest() -> None:
    data = b"\xde\xad\xbe\xef"

    assert guard._hash_region(data) == guard._hash_region(data)


def testReconstructSeed_whenCalledTwice_producesTheSameSeed() -> None:
    assert guard._reconstruct_seed() == guard._reconstruct_seed()


def testReconstructSeed_whenInspected_isNotAllZero() -> None:
    seed = guard._reconstruct_seed()

    assert seed != b"\x00" * len(seed)


def testChacha20Xor_whenRunTwice_recoversThePlaintext() -> None:
    plaintext = b"hello, world! 1234567890"
    key = bytes(range(32))
    nonce = bytes(16)
    data = bytearray(plaintext)

    guard._chacha20_xor(data, key, nonce)
    assert bytes(data) != plaintext

    guard._chacha20_xor(data, key, nonce)
    assert bytes(data) == plaintext


def testChacha20Xor_whenRfc8439Example_matchesTheVector() -> None:
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, sunscreen would be it."
    )
    key = bytes(range(32))
    nonce = bytes.fromhex("01000000000000000000004a00000000")
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    data = bytearray(plaintext)

    guard._chacha20_xor(data, key, nonce)

    assert bytes(data) == expected


def testDeriveKey_whenCodeHashDiffers_producesDifferentKeys() -> None:
    code_a = guard._hash_region(b"\x01\x02\x03\x04")
    code_b = guard._hash_region(b"\x01\x02\x03\x05")
    seed = guard._reconstruct_seed()

    key_a = guard._derive_key(code_a, seed)
    key_b = guard._derive_key(code_b, seed)

    assert key_a != key_b


def testDeriveKey_whenSameInputs_producesSameKey() -> None:
    code = guard._hash_region(b"\x01\x02\x03\x04")
    seed = guard._reconstruct_seed()

    assert guard._derive_key(code, seed) == guard._derive_key(code, seed)
