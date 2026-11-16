"""Tests of the payload cipher."""

import pytest

from rasp_packer.android import cipher

_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

# The frame the native runtime's tests decrypt (runtime/tests/android/payload/cipher_test.cpp), so both
# sides of the cipher are checked against the same bytes.
_RUNTIME_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
_RUNTIME_FRAME = bytes.fromhex(
    "000102030405060708090a0bfd936d205b62cb34deee5ad3ec787d17e916c0863c1197998af841a210b2864884e142d3"
    "8970d4b801065bba1ce0ea033decc83795498aab32dab568f324b2f60a179cb98d710c82a16f3ec86a19bd9cfaad3753"
    "0119d04a7938d06cb41261d43e94d233cbe6e8bfc182b89601363c917a"
)
_RUNTIME_PLAINTEXT = (
    b"the runtime test frame: longer than one 64-byte ChaCha20 block, "
    b"so the keystream spans two blocks"
)

# Test case 74 of Project Wycheproof's chacha20_poly1305_test.json, which has no associated data. The
# native runtime's tests decrypt it too.
_WYCHEPROOF_KEY = bytes.fromhex(
    "fe6e55bdaed1f7284ca5fc0f8c5f2b8df56dc0f49e8ca66a41995e783351f901"
)
_WYCHEPROOF_FRAME = bytes.fromhex(
    "17c86a8abbb7e003acde2799"
    "d0102f6c258bf49742cec34cf2d0fedf23d105fb4c84cf98515e1bc9a64f8ad5be8f0721bde50645d00083c3a263a3"
    "1053b760245f52ae2866a5ec83b19f61be1d30d5c5d9fecc4cbbe08fd385813a2aa39a00ff9c10f7f23702add1e4b2"
    "ffa31c"
    "41865fc71de12b19612127ce49993bb0"
)
_WYCHEPROOF_PLAINTEXT = bytes.fromhex(
    "b429eb80fb8fe8baeda0c85b9c333458e7c2992e558475069d12d45c22217564121588032297eff56783742a5fc22d74"
    "10ffb29d66098661d76f126c3c27689e43b37267cac5a3a6d3ab49e391da29cd3054a5692e2807e4c3ea46c8761d50f5"
    "92"
)


def testDecrypt_whenSameKey_returnsThePlaintext() -> None:
    plaintext = b"the original classes.dex bytes"
    assert (
        cipher.decrypt(_KEY, cipher.encrypt(_KEY, cipher.new_nonce(), plaintext))
        == plaintext
    )


def testDecrypt_whenPlaintextEmpty_returnsEmptyBytes() -> None:
    assert cipher.decrypt(_KEY, cipher.encrypt(_KEY, cipher.new_nonce(), b"")) == b""


def testDecrypt_whenPlaintextSpansBlocks_returnsThePlaintext() -> None:
    plaintext = bytes(range(256)) * 40
    assert (
        cipher.decrypt(_KEY, cipher.encrypt(_KEY, cipher.new_nonce(), plaintext))
        == plaintext
    )


def testEncrypt_whenSameInput_producesADifferentFrame() -> None:
    assert cipher.encrypt(_KEY, cipher.new_nonce(), b"same input") != cipher.encrypt(
        _KEY, cipher.new_nonce(), b"same input"
    )


def testEncrypt_whenCalled_hidesThePlaintext() -> None:
    assert b"secret" not in cipher.encrypt(_KEY, cipher.new_nonce(), b"a secret value")


def testEncrypt_whenKeySizeWrong_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        cipher.encrypt(b"too short", cipher.new_nonce(), b"data")


def testEncrypt_whenNonceSizeWrong_raisesValueError() -> None:
    with pytest.raises(ValueError, match="12 bytes"):
        cipher.encrypt(_KEY, b"too short", b"data")


def testDecrypt_whenKeyWrong_raisesCipherError() -> None:
    frame = cipher.encrypt(_KEY, cipher.new_nonce(), b"data")
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(bytes(32), frame)


def testDecrypt_whenTagTampered_raisesCipherError() -> None:
    frame = bytearray(cipher.encrypt(_KEY, cipher.new_nonce(), b"data to protect"))
    frame[-1] ^= 0x01
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(_KEY, bytes(frame))


def testDecrypt_whenFrameTooShort_raisesCipherError() -> None:
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(_KEY, b"short")


def testDecrypt_whenGivenTheRuntimesTestFrame_returnsItsPlaintext() -> None:
    assert cipher.decrypt(_RUNTIME_KEY, _RUNTIME_FRAME) == _RUNTIME_PLAINTEXT


def testEncrypt_whenGivenTheRuntimesTestNonce_producesTheRuntimesTestFrame() -> None:
    nonce = _RUNTIME_FRAME[: cipher.NONCE_SIZE]

    assert cipher.encrypt(_RUNTIME_KEY, nonce, _RUNTIME_PLAINTEXT) == _RUNTIME_FRAME


def testDecrypt_whenTheKeySizeIsWrong_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        cipher.decrypt(b"too short", _RUNTIME_FRAME)


def testDecrypt_whenGivenTheWycheproofVector_returnsItsPlaintext() -> None:
    assert cipher.decrypt(_WYCHEPROOF_KEY, _WYCHEPROOF_FRAME) == _WYCHEPROOF_PLAINTEXT


def testEncrypt_whenGivenTheWycheproofNonce_producesTheWycheproofFrame() -> None:
    nonce = _WYCHEPROOF_FRAME[: cipher.NONCE_SIZE]

    assert (
        cipher.encrypt(_WYCHEPROOF_KEY, nonce, _WYCHEPROOF_PLAINTEXT)
        == _WYCHEPROOF_FRAME
    )
