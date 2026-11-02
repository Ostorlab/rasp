"""Independent tests for standalone authenticated files."""

import pytest
from cryptography.hazmat.primitives.ciphers import aead

from rasp_whitebox import codec


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 4097])
def testEncrypt_whenBinaryInput_matchesIndependentAead(size: int) -> None:
    key = bytes(range(16))
    plaintext = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    record = codec.encrypt(key, plaintext)
    assert record[:4] == b"WBX1"
    assert len(record) == size + 32
    assert aead.AESGCM(key).decrypt(record[4:16], record[16:], record[:16]) == plaintext
    assert codec.decrypt(key, record) == plaintext


@pytest.mark.parametrize("offset", range(43))
def testDecrypt_whenAnyByteChanged_rejectsRecord(offset: int) -> None:
    key = bytes(16)
    record = bytearray(codec.encrypt(key, b"hello world"))
    record[offset] ^= 1
    with pytest.raises(codec.Error):
        codec.decrypt(key, bytes(record))


@pytest.mark.parametrize("length", range(43))
def testDecrypt_whenTruncated_rejectsRecord(length: int) -> None:
    record = codec.encrypt(bytes(16), b"hello world")
    with pytest.raises(codec.Error):
        codec.decrypt(bytes(16), record[:length])


def testDecrypt_whenWrongKey_rejectsRecord() -> None:
    record = codec.encrypt(bytes(16), b"secret")
    with pytest.raises(codec.Error, match="authentication"):
        codec.decrypt(b"\x01" * 16, record)


@pytest.mark.parametrize("length", [0, 15, 17, 32])
def testEncrypt_whenInvalidKey_rejectsKey(length: int) -> None:
    with pytest.raises(codec.Error, match="16"):
        codec.encrypt(bytes(length), b"secret")


def testEncrypt_whenRepeated_usesFreshNonce() -> None:
    records = {codec.encrypt(bytes(16), b"same") for _ in range(32)}
    assert len(records) == 32


def testEncrypt_whenOverLimit_rejectsInput() -> None:
    with pytest.raises(codec.Error, match="limit"):
        codec.encrypt(bytes(16), bytes(codec.MAX_PLAINTEXT + 1))
