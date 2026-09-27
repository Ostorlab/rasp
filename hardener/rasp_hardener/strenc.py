"""Compile-time string / constant encryption (design §6, §2 consteval string encryption).

Plaintext strings that would otherwise sit in ``.rodata`` (detector names, class paths, JNI signatures) are
XOR-encrypted at build time with a per-build key stream and emitted as byte arrays. The native runtime
decrypts each into a stack buffer only at the moment of use (see ``strobf.c``), so a static ``strings`` dump
of the ``.so`` yields nothing useful.

The transform below is a keyed rolling XOR. It is deliberately simple and self-inverse so the C side reverses
it byte-for-byte with no tables; it is not a substitute for the report MAC or hardware attestation, whose job
is to stop forgery — this only removes cleartext literals from the binary. The key stream comes from the
build seed (:class:`~rasp_hardener.seed.BuildProfile`), so it differs per build.

`obfuscate` and the C `rasp_strobf_decode` MUST stay byte-identical; :mod:`tests.test_emit_native` compiles
the generated header against the C decoder and asserts the round trip, which fails loudly if they drift.
"""

from __future__ import annotations

from dataclasses import dataclass

KEY_LEN = 32


def _keybyte(string_key: bytes, idx: int, i: int) -> int:
    """The key byte applied to position `i` of the string with table index `idx`.

    Mixes the per-build key stream with the string's index and offset so identical plaintexts at different
    indices encrypt differently and repeated characters within a string do not repeat in the ciphertext.
    """
    return string_key[(idx * 7 + i) % KEY_LEN] ^ ((idx + i) & 0xFF)


def obfuscate(plaintext: str, string_key: bytes, idx: int) -> bytes:
    """Encrypt one UTF-8 string for table slot `idx`. Returns the ciphertext bytes (no NUL terminator)."""
    if len(string_key) != KEY_LEN:
        raise ValueError(f"string_key must be {KEY_LEN} bytes")
    raw = plaintext.encode("utf-8")
    return bytes(b ^ _keybyte(string_key, idx, i) for i, b in enumerate(raw))


def deobfuscate(cipher: bytes, string_key: bytes, idx: int) -> str:
    """Inverse of :func:`obfuscate` (used in tests; the runtime uses the C decoder)."""
    raw = bytes(b ^ _keybyte(string_key, idx, i) for i, b in enumerate(cipher))
    return raw.decode("utf-8")


@dataclass(frozen=True)
class EncryptedString:
    name: str          # C identifier suffix, e.g. "TARGET_CLASS"
    plaintext: str     # kept for the header comment / debugging only
    cipher: bytes      # what actually lands in the binary


def encrypt_table(entries: dict[str, str], string_key: bytes) -> list[EncryptedString]:
    """Encrypt an ordered ``{name: plaintext}`` table. Table order fixes each entry's index/key."""
    out: list[EncryptedString] = []
    for idx, (name, plaintext) in enumerate(entries.items()):
        out.append(EncryptedString(name=name, plaintext=plaintext, cipher=obfuscate(plaintext, string_key, idx)))
    return out
