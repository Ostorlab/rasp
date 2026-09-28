"""Authenticated resource packages bound to an integrity root and resource identity.

The bytes can be assets or class files. This module does not implement a DEX or JVM
class loader. Native opening authenticates before copying plaintext to the caller.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from rasp_hardener import whitebox

MAGIC = b"RAP1"
HEADER_LEN = 48
TAG_LEN = 32
MAX_BYTES = 16 * 1024 * 1024


def derive_keys(base_key: bytes, integrity_root: bytes) -> tuple[bytes, bytes]:
    if len(base_key) != 32 or len(integrity_root) != 32:
        raise ValueError("base key and integrity root must each be 32 bytes")
    encryption = hmac.new(base_key, b"rasp/assets/enc/v1" + integrity_root, hashlib.sha256).digest()[:16]
    authentication = hmac.new(base_key, b"rasp/assets/mac/v1" + integrity_root, hashlib.sha256).digest()
    return encryption, authentication


def tables(base_key: bytes, integrity_root: bytes) -> whitebox.WhiteBoxTables:
    encryption, authentication = derive_keys(base_key, integrity_root)
    encoding_seed = hmac.new(authentication, b"rasp/assets/encoding/v1", hashlib.sha256).digest()
    return whitebox.generate(encryption, encoding_seed=encoding_seed)


def seal(data: bytes, identity: str, base_key: bytes, integrity_root: bytes, nonce: bytes | None = None) -> bytes:
    if len(data) > MAX_BYTES or identity == "":
        raise ValueError("invalid resource size or identity")
    nonce = os.urandom(12) if nonce is None else nonce
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes; never reuse it with the same key")
    _, authentication = derive_keys(base_key, integrity_root)
    header = MAGIC + nonce + hashlib.sha256(identity.encode("utf-8")).digest()
    ciphertext = whitebox.ctr(tables(base_key, integrity_root), nonce, data)
    body = header + ciphertext
    return body + hmac.new(authentication, body, hashlib.sha256).digest()


def open_package(package: bytes, identity: str, base_key: bytes, integrity_root: bytes) -> bytes:
    if len(package) < HEADER_LEN + TAG_LEN or len(package) > MAX_BYTES + HEADER_LEN + TAG_LEN or identity == "":
        raise ValueError("invalid package size or identity")
    _, authentication = derive_keys(base_key, integrity_root)
    expected = hmac.new(authentication, package[:-TAG_LEN], hashlib.sha256).digest()
    if hmac.compare_digest(expected, package[-TAG_LEN:]) is False:
        raise ValueError("package authentication failed")
    if package[:4] != MAGIC or hmac.compare_digest(package[16:48], hashlib.sha256(identity.encode()).digest()) is False:
        raise ValueError("package identity mismatch")
    return whitebox.ctr(tables(base_key, integrity_root), package[4:16], package[HEADER_LEN:-TAG_LEN])
