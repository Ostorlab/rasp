"""Authenticated encryption for the protected payload.

The packer encrypts the app's original code with this. The native runtime
decrypts it, in C, after its pre-decryption checks pass. The scheme uses only
HMAC-SHA256, so the native side needs nothing more than a SHA-256
implementation.

The master key is 32 bytes. Two subkeys are derived from it, one for the
keystream and one for the authentication tag, so the same key never does both
jobs. Encryption is counter mode: each 32-byte block of the keystream is the
HMAC-SHA256 of the nonce and a block counter, and the plaintext is XORed with
it. The tag authenticates the header and the ciphertext (encrypt-then-MAC).

Frame layout, in order:

    magic    4 bytes   MAGIC
    version  1 byte    FRAME_VERSION
    nonce    16 bytes  random, one per frame
    body     n bytes   ciphertext, the same length as the plaintext
    tag      32 bytes  HMAC-SHA256 over magic .. body

TODO(hardening): the hardened build replaces this with AES evaluated through the
white-box tables, so no usable key is present in the clear. See the repo TODO.
"""

import hashlib
import hmac
import os

MAGIC = b"RASP"
FRAME_VERSION = 1
KEY_SIZE = 32

_NONCE_SIZE = 16
_TAG_SIZE = 32
_HEADER_SIZE = len(MAGIC) + 1 + _NONCE_SIZE
_COUNTER_SIZE = 8
_BLOCK_SIZE = 32

_ENCRYPT_LABEL = b"rasp/android/encrypt/v1"
_AUTHENTICATE_LABEL = b"rasp/android/authenticate/v1"


class CipherError(Exception):
    """A frame could not be decrypted: wrong format, version or tag."""


def new_key() -> bytes:
    """Returns a fresh random master key."""
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts and authenticates plaintext, returning one frame.

    Args:
        key: The 32-byte master key.
        plaintext: The bytes to protect.

    Returns:
        The frame: header, ciphertext and tag.

    Raises:
        ValueError: The key is not 32 bytes.
    """
    _check_key(key)
    nonce = os.urandom(_NONCE_SIZE)
    header = MAGIC + bytes([FRAME_VERSION]) + nonce
    body = _apply_keystream(key, nonce, plaintext)
    return header + body + _tag(key, header + body)


def decrypt(key: bytes, frame: bytes) -> bytes:
    """Verifies a frame's tag and returns its plaintext.

    The native runtime does this in C; this is the reference, used by the tests.

    Args:
        key: The 32-byte master key.
        frame: A frame produced by encrypt.

    Returns:
        The plaintext.

    Raises:
        ValueError: The key is not 32 bytes.
        CipherError: The frame is malformed or its tag does not verify.
    """
    _check_key(key)
    if len(frame) < _HEADER_SIZE + _TAG_SIZE:
        raise CipherError("frame is too short")
    if frame[: len(MAGIC)] != MAGIC:
        raise CipherError("frame has the wrong magic")
    if frame[len(MAGIC)] != FRAME_VERSION:
        raise CipherError(f"frame version {frame[len(MAGIC)]} is not supported")
    header = frame[:_HEADER_SIZE]
    body = frame[_HEADER_SIZE : len(frame) - _TAG_SIZE]
    tag = frame[len(frame) - _TAG_SIZE :]
    if not hmac.compare_digest(tag, _tag(key, header + body)):
        raise CipherError("frame tag does not verify")
    return _apply_keystream(key, header[len(MAGIC) + 1 :], body)


def _check_key(key: bytes) -> None:
    """Raises ValueError when `key` is not KEY_SIZE bytes."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")


def _subkey(key: bytes, label: bytes) -> bytes:
    """Derives the subkey for `label` from the master key."""
    return hmac.new(key, label, hashlib.sha256).digest()


def _apply_keystream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """XORs `data` with the keystream of `key` and `nonce`, which both encrypts and decrypts."""
    subkey = _subkey(key, _ENCRYPT_LABEL)
    output = bytearray()
    for counter, start in enumerate(range(0, len(data), _BLOCK_SIZE)):
        chunk = data[start : start + _BLOCK_SIZE]
        block = hmac.new(
            subkey, nonce + counter.to_bytes(_COUNTER_SIZE, "big"), hashlib.sha256
        ).digest()
        masked = int.from_bytes(chunk, "big") ^ int.from_bytes(
            block[: len(chunk)], "big"
        )
        output += masked.to_bytes(len(chunk), "big")
    return bytes(output)


def _tag(key: bytes, data: bytes) -> bytes:
    """Returns the authentication tag of `data`."""
    return hmac.new(_subkey(key, _AUTHENTICATE_LABEL), data, hashlib.sha256).digest()
