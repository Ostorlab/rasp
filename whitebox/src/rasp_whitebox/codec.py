"""Trusted-host AES-128-GCM oracle for the standalone WBX1 file format."""

import secrets

from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import aead

MAGIC = b"WBX1"
MAX_PLAINTEXT = 16 * 1024 * 1024
OVERHEAD = 32


class Error(Exception):
    """A key, input, or authenticated record is invalid."""


def _validate_key(key: bytes) -> None:
    """Require one AES-128 key, represented as raw bytes."""
    if len(key) != 16:
        raise Error("key must contain exactly 16 raw bytes")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Seal a bounded input using a fresh 96-bit nonce and authenticated header."""
    _validate_key(key)
    if len(plaintext) > MAX_PLAINTEXT:
        raise Error("plaintext exceeds the 16 MiB limit")
    nonce = secrets.token_bytes(12)
    header = MAGIC + nonce
    return header + aead.AESGCM(key).encrypt(nonce, plaintext, header)


def decrypt(key: bytes, record: bytes) -> bytes:
    """Authenticate the complete record before returning plaintext."""
    _validate_key(key)
    if len(record) < OVERHEAD or len(record) > MAX_PLAINTEXT + OVERHEAD:
        raise Error("record length is outside the supported limit")
    if record[:4] != MAGIC:
        raise Error("unsupported record format")
    try:
        return aead.AESGCM(key).decrypt(record[4:16], record[16:], record[:16])
    except exceptions.InvalidTag as error:
        raise Error("authentication failed") from error
