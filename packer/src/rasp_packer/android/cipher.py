"""Authenticated encryption of the protected payload, with ChaCha20-Poly1305.

The packer encrypts the app's original code with ChaCha20-Poly1305, as RFC 8439
defines it, using the `cryptography` package. The native runtime decrypts it
with the same algorithm from TF-PSA-Crypto, after its pre-decryption checks pass.

Each protected app gets one random 32-byte key, which encrypts all of its frames:
the class map and every business dex. Each frame gets its own random nonce,
stored at the start of the frame so the runtime can read it. There is no
associated data.

Frame layout, in order:

    nonce    12 bytes  random, one per frame
    body     n bytes   ciphertext, the same length as the plaintext
    tag      16 bytes  the Poly1305 tag
"""

import os

from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import aead

from rasp_packer import errors

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


class CipherError(errors.Error):
    """A frame could not be decrypted: it is too short, or its tag does not verify."""


def new_key() -> bytes:
    """Returns a fresh random key."""
    return aead.ChaCha20Poly1305.generate_key()


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts and authenticates plaintext, returning one frame.

    Args:
        key: The 32-byte key.
        plaintext: The bytes to protect.

    Returns:
        The frame: nonce, ciphertext and tag.

    Raises:
        ValueError: The key is not 32 bytes.
    """
    nonce = os.urandom(NONCE_SIZE)
    return nonce + aead.ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def decrypt(key: bytes, frame: bytes) -> bytes:
    """Verifies a frame's tag and returns its plaintext.

    The native runtime does this on the device; this is the reference, used by the tests.

    Args:
        key: The 32-byte key.
        frame: A frame produced by encrypt.

    Returns:
        The plaintext.

    Raises:
        ValueError: The key is not 32 bytes.
        CipherError: The frame is too short, or its tag does not verify.
    """
    chacha = aead.ChaCha20Poly1305(key)
    if len(frame) < NONCE_SIZE + TAG_SIZE:
        raise CipherError("frame is too short")
    try:
        return chacha.decrypt(frame[:NONCE_SIZE], frame[NONCE_SIZE:], None)
    except exceptions.InvalidTag as error:
        raise CipherError("frame tag does not verify") from error
