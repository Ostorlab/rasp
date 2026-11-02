"""Tests for the runtime library's self-encryption."""

import hashlib

import pytest

from rasp_packer import errors
from rasp_packer.android import self_encrypt
from tests.rasp_packer import conftest

_LIBRARY = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()


def _section(library: bytes, name: str) -> self_encrypt._Section:
    header = self_encrypt._read_header(library)
    return self_encrypt._find_section(
        self_encrypt._read_sections(library, header), name
    )


def _section_names(library: bytes) -> set[str]:
    header = self_encrypt._read_header(library)
    return {section.name for section in self_encrypt._read_sections(library, header)}


def _decrypt_text(library: bytes) -> bytes:
    """Reverses the encryption of .text the way the bootstrap would, and returns the recovered .text."""
    header = self_encrypt._read_header(library)
    sections = self_encrypt._read_sections(library, header)
    meta = self_encrypt._find_section(
        sections, self_encrypt.SECTION_RENAMES[".packmeta"]
    )
    stub = self_encrypt._find_section(
        sections, self_encrypt.SECTION_RENAMES[".stubcode"]
    )
    fields = self_encrypt._META_HEADER.unpack_from(library, meta.offset)
    words = [
        fields[1],
        fields[3],
        fields[5],
        fields[7],
        fields[9],
        fields[10],
        fields[12],
        fields[13],
    ]
    ikm = b"".join(word.to_bytes(4, "little") for word in words)
    salt = hashlib.sha256(library[stub.offset : stub.offset + stub.size]).digest()
    key = self_encrypt._derive_key(ikm, salt)

    data = bytearray(library)
    for index in range(fields[2]):
        offset = (
            meta.offset
            + self_encrypt._META_HEADER.size
            + index * self_encrypt._REGION.size
        )
        vaddr, size, _is_code, _reserved, nonce = self_encrypt._REGION.unpack_from(
            library, offset
        )
        section = self_encrypt._section_at(sections, vaddr)
        file_off = section.offset + (vaddr - section.addr)
        data[file_off : file_off + size] = self_encrypt._chacha20(
            bytes(data[file_off : file_off + size]), key, nonce
        )
    text = self_encrypt._find_section(sections, ".text")
    return bytes(data[text.offset : text.offset + text.size])


def test_encryptLibrary_keepsTheSize() -> None:
    assert len(self_encrypt.encrypt_library(_LIBRARY)) == len(_LIBRARY)


def test_encryptLibrary_encryptsTheTextAtRest() -> None:
    encrypted = self_encrypt.encrypt_library(_LIBRARY)
    text = _section(_LIBRARY, ".text")
    assert (
        encrypted[text.offset : text.offset + text.size]
        != _LIBRARY[text.offset : text.offset + text.size]
    )


def test_encryptLibrary_recoversTheTextWhenDecrypted() -> None:
    encrypted = self_encrypt.encrypt_library(_LIBRARY)
    text = _section(_LIBRARY, ".text")
    assert _decrypt_text(encrypted) == _LIBRARY[text.offset : text.offset + text.size]


def test_encryptLibrary_marksTheMetadataPacked() -> None:
    encrypted = self_encrypt.encrypt_library(_LIBRARY)
    meta = _section(encrypted, self_encrypt.SECTION_RENAMES[".packmeta"])
    assert self_encrypt._PACKED_FLAG.unpack_from(encrypted, meta.offset)[0] == 1


def test_encryptLibrary_scrubsTheTelltaleSectionNames() -> None:
    names = _section_names(self_encrypt.encrypt_library(_LIBRARY))
    assert ".stubcode" not in names
    assert ".packmeta" not in names
    assert ".text.hot" in names
    assert ".data.rel" in names


def test_encryptLibrary_neutralisesTheSoname() -> None:
    encrypted = self_encrypt.encrypt_library(_LIBRARY)
    dynstr = _section(encrypted, ".dynstr")
    assert b"librasp.so" not in encrypted[dynstr.offset : dynstr.offset + dynstr.size]
    assert (
        self_encrypt.NEUTRAL_SONAME
        in encrypted[dynstr.offset : dynstr.offset + dynstr.size]
    )


def test_encryptLibrary_usesFreshKeyingMaterialEachTime() -> None:
    assert self_encrypt.encrypt_library(_LIBRARY) != self_encrypt.encrypt_library(
        _LIBRARY
    )


def test_encryptLibrary_whenNotAnElf_raises() -> None:
    with pytest.raises(errors.InvalidRuntimeError):
        self_encrypt.encrypt_library(b"not an elf file")


def test_encryptLibrary_whenAlreadyPacked_raises() -> None:
    encrypted = self_encrypt.encrypt_library(_LIBRARY)
    with pytest.raises(errors.InvalidRuntimeError):
        self_encrypt.encrypt_library(encrypted)
