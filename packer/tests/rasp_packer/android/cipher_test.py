"""Tests of the payload cipher."""

import pytest

from rasp_packer.android import cipher


def testEncryptDecrypt_roundTrips() -> None:
    key = cipher.new_key()
    plaintext = b"the original classes.dex bytes"
    assert cipher.decrypt(key, cipher.encrypt(key, plaintext)) == plaintext


def testEncryptDecrypt_emptyPlaintext_roundTrips() -> None:
    key = cipher.new_key()
    assert cipher.decrypt(key, cipher.encrypt(key, b"")) == b""


def testEncryptDecrypt_multipleBlocks_roundTrips() -> None:
    key = cipher.new_key()
    plaintext = bytes(range(256)) * 40
    assert cipher.decrypt(key, cipher.encrypt(key, plaintext)) == plaintext


def testEncrypt_producesADifferentFrameEachTime() -> None:
    key = cipher.new_key()
    assert cipher.encrypt(key, b"same input") != cipher.encrypt(key, b"same input")


def testEncrypt_doesNotLeakThePlaintext() -> None:
    key = cipher.new_key()
    assert b"secret" not in cipher.encrypt(key, b"a secret value")


def testEncrypt_withWrongKeySize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        cipher.encrypt(b"too short", b"data")


def testDecrypt_withWrongKey_raisesCipherError() -> None:
    frame = cipher.encrypt(cipher.new_key(), b"data")
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(cipher.new_key(), frame)


def testDecrypt_withTamperedTag_raisesCipherError() -> None:
    key = cipher.new_key()
    frame = bytearray(cipher.encrypt(key, b"data to protect"))
    frame[-1] ^= 0x01
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(key, bytes(frame))


def testDecrypt_withShortFrame_raisesCipherError() -> None:
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(cipher.new_key(), b"short")
