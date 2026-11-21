"""Self-encryption of the runtime library, ``librasp.so``.

The runtime carries a load-time bootstrap (``runtime/android/src/selfdecrypt``) that decrypts the library's own code and
read-only data before any of it runs. This module is the build-time half: it encrypts the shipped ``librasp.so``'s
``.text``, ``.rodata``, ``.eh_frame`` and ``.eh_frame_hdr`` with ChaCha20, records the regions and the key-derivation
material in the plaintext ``.packmeta`` section the bootstrap reads, renames the telltale bootstrap sections, and
neutralises the library's soname.

No key is stored. The ChaCha20 content key is derived here with HKDF-SHA256 (RFC 5869) from per-build random input
keying material (IKM) and a SHA-256 self-hash over the clear ``.stubcode`` bytes; the bootstrap derives the same key at
load. The IKM is written into ``.packmeta`` as eight scattered words, never as one contiguous blob, and ``.packmeta`` is a
different section from the hashed ``.stubcode``, so writing the IKM never changes the self-hash. The cipher is raw
ChaCha20 (not the payload's ChaCha20-Poly1305 frame cipher): the bootstrap decrypts in place with a self-contained stream
cipher that must run before the payload cipher's TF-PSA-Crypto code, which is itself in the encrypted ``.text``.

The library layout is never rebuilt: bytes are edited in place at their file offsets, so every section keeps its address
and the bootstrap's recorded regions stay valid.
"""

import dataclasses
import hashlib
import os
import struct
from typing import Any

import cryptography.hazmat.primitives.ciphers as ciphers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rasp_packer import errors

META_SECTION = ".packmeta"
STUBCODE_SECTION = ".stubcode"
ENCRYPT_SECTIONS = (".text", ".rodata", ".data.rel.ro", ".eh_frame", ".eh_frame_hdr")
MAX_REGIONS = 64
KEY_LEN = 32
IKM_LEN = 32
IKM_WORDS = 8
NONCE_LEN = 16

# Post-encryption section renames, so the shipped library does not advertise its runtime. The replacements are no
# longer than the originals, so they are edited in place.
SECTION_RENAMES = {
    ".stubcode": ".text.hot",
    ".stubrodata": ".rodata.cst",
    ".packmeta": ".data.rel",
}
# A neutral soname (<= the 10 bytes of "librasp.so"), so the shipped library does not carry the project name.
NEUTRAL_SONAME = b"libjni.so"

_ELF_HEADER64 = struct.Struct("<HHIQQQIHHHHHH")
_ELF_HEADER32 = struct.Struct("<HHIIIIIHHHHHH")
_SECTION_HEADER64 = struct.Struct("<IIQQQQIIQQ")
_SECTION_HEADER32 = struct.Struct("<IIIIIIIIII")
_PROGRAM_HEADER64 = struct.Struct("<IIQQQQQQ")
_PROGRAM_HEADER32 = struct.Struct("<IIIIIIII")
_DYNAMIC_ENTRY64 = struct.Struct("<qQ")
_DYNAMIC_ENTRY32 = struct.Struct("<iI")
_RELA64 = struct.Struct("<QQq")
_RELA32 = struct.Struct("<IIi")
_REL64 = struct.Struct("<QQ")
_REL32 = struct.Struct("<II")
_RELR64 = struct.Struct("<Q")
_RELR32 = struct.Struct("<I")
_META_HEADER = struct.Struct("<15I")
_META_TEXT_DIGEST = struct.Struct("<32s")
_REGION = struct.Struct("<IIII16s")
_PACKED_FLAG = struct.Struct("<I")
# The positions of the IKM's words among the metadata header's fields.
_IKM_FIELDS = (1, 3, 5, 7, 9, 10, 12, 13)
_ELF_HEADER_OFFSET = 16

_SHT_RELA = 4
_SHT_NOBITS = 8
_SHT_REL = 9
_SHT_RELR = 19
_PT_GNU_RELRO = 0x6474E552
_DT_SONAME = 14
_DT_NULL = 0


@dataclasses.dataclass(frozen=True)
class _Section:
    """One ELF section header, reduced to what the encryptor needs."""

    name: str
    type: int
    addr: int
    offset: int
    size: int
    entsize: int


@dataclasses.dataclass(frozen=True)
class _ElfHeader:
    """The ELF header fields the encryptor uses, with the structs of its 32- or 64-bit class."""

    shoff: int
    shentsize: int
    shnum: int
    shstrndx: int
    phoff: int
    phentsize: int
    phnum: int
    word: int
    shdr: struct.Struct
    phdr: struct.Struct
    dyn: struct.Struct
    rel: struct.Struct
    rela: struct.Struct
    relr: struct.Struct


@dataclasses.dataclass(frozen=True)
class _Region:
    """One contiguous byte range the encryptor encrypted."""

    vaddr: int
    size: int
    is_code: int
    nonce: bytes


def _malformed() -> errors.InvalidRuntimeError:
    """The error for a library whose tables reach outside the file."""
    return errors.InvalidRuntimeError("the runtime library is truncated or malformed")


def _unpack(
    entry: struct.Struct, data: bytes | bytearray, offset: int
) -> tuple[Any, ...]:
    """Unpacks ``entry`` at ``offset``, or raises when it reaches outside ``data``."""
    if offset < 0 or offset + entry.size > len(data):
        raise _malformed()
    return entry.unpack_from(data, offset)


def _string_end(data: bytes | bytearray, start: int) -> int:
    """The offset of the NUL that ends the string at ``start``, or raises when there is none."""
    end = data.find(b"\x00", start) if 0 <= start < len(data) else -1
    if end == -1:
        raise _malformed()
    return end


def _read_header(data: bytes | bytearray) -> _ElfHeader:
    """Parses the ELF header, or raises when the file is not a little-endian ELF object."""
    if len(data) < 52 or data[0:4] != b"\x7fELF":
        raise errors.InvalidRuntimeError("the runtime library is not an ELF file")
    if data[4] not in (1, 2) or data[5] != 1:
        raise errors.InvalidRuntimeError(
            "the runtime library is not a little-endian ELF object"
        )
    is64 = data[4] == 2
    if is64:
        head, word = _ELF_HEADER64, 8
        shdr, phdr, dyn = _SECTION_HEADER64, _PROGRAM_HEADER64, _DYNAMIC_ENTRY64
        rel, rela, relr = _REL64, _RELA64, _RELR64
    else:
        head, word = _ELF_HEADER32, 4
        shdr, phdr, dyn = _SECTION_HEADER32, _PROGRAM_HEADER32, _DYNAMIC_ENTRY32
        rel, rela, relr = _REL32, _RELA32, _RELR32
    fields = head.unpack_from(data, _ELF_HEADER_OFFSET)
    return _ElfHeader(
        phoff=fields[4],
        shoff=fields[5],
        phentsize=fields[8],
        phnum=fields[9],
        shentsize=fields[10],
        shnum=fields[11],
        shstrndx=fields[12],
        word=word,
        shdr=shdr,
        phdr=phdr,
        dyn=dyn,
        rel=rel,
        rela=rela,
        relr=relr,
    )


def _read_sections(data: bytes | bytearray, header: _ElfHeader) -> list[_Section]:
    """Parses the section headers with their names."""
    if header.shoff == 0 or header.shnum == 0:
        raise errors.InvalidRuntimeError("the runtime library has no section headers")
    if header.shentsize != header.shdr.size:
        raise errors.InvalidRuntimeError(
            "the runtime library has an unexpected section header size"
        )

    raw: list[tuple[int, int, int, int, int, int]] = []
    for index in range(header.shnum):
        name, stype, _flags, addr, offset, size, _link, _info, _align, entsize = (
            _unpack(header.shdr, data, header.shoff + index * header.shentsize)
        )
        if stype != _SHT_NOBITS and offset + size > len(data):
            raise _malformed()
        raw.append((name, stype, addr, offset, size, entsize))

    if header.shstrndx >= header.shnum:
        raise _malformed()
    strtab_offset = raw[header.shstrndx][3]
    sections: list[_Section] = []
    for name, stype, addr, offset, size, entsize in raw:
        start = strtab_offset + name
        end = _string_end(data, start)
        sections.append(
            _Section(
                name=data[start:end].decode("ascii", errors="replace"),
                type=stype,
                addr=addr,
                offset=offset,
                size=size,
                entsize=entsize,
            )
        )
    return sections


def _find_section(sections: list[_Section], name: str) -> _Section:
    """Returns the first section with the given name, or raises."""
    for section in sections:
        if section.name == name:
            return section
    raise errors.InvalidRuntimeError(f"the runtime library has no {name} section")


def _relro_range(data: bytes | bytearray, header: _ElfHeader) -> tuple[int, int] | None:
    """Returns the ``[start, end)`` vaddr range of PT_GNU_RELRO, or None."""
    if header.phentsize != header.phdr.size:
        return None
    for index in range(header.phnum):
        fields = _unpack(header.phdr, data, header.phoff + index * header.phentsize)
        if fields[0] != _PT_GNU_RELRO:
            continue
        # The 64-bit program header reorders flags ahead of offset, so vaddr and memsz sit at different indices.
        vaddr, memsz = (
            (fields[3], fields[6]) if header.word == 8 else (fields[2], fields[5])
        )
        return (vaddr, vaddr + memsz)
    return None


def _reloc_offsets(
    data: bytes | bytearray, sections: list[_Section], header: _ElfHeader
) -> set[int]:
    """Collects every vaddr that a dynamic relocation patches."""
    offsets: set[int] = set()
    for section in sections:
        if section.type == _SHT_RELA:
            offsets.update(_table_offsets(data, section, header.rela))
        elif section.type == _SHT_REL:
            offsets.update(_table_offsets(data, section, header.rel))
        elif section.type == _SHT_RELR:
            offsets.update(_relr_offsets(data, section, header))
    return offsets


def _table_offsets(
    data: bytes | bytearray, section: _Section, entry: struct.Struct
) -> set[int]:
    """The ``r_offset`` of each relocation entry in ``section``."""
    entsize = section.entsize if section.entsize > 0 else entry.size
    return {
        _unpack(entry, data, pos)[0]
        for pos in range(section.offset, section.offset + section.size, entsize)
    }


def _relr_offsets(
    data: bytes | bytearray, section: _Section, header: _ElfHeader
) -> set[int]:
    """Decodes a SHT_RELR section into the set of relocated vaddrs."""
    offsets: set[int] = set()
    word = header.word
    bits_per_entry = word * 8 - 1
    base = 0
    for pos in range(section.offset, section.offset + section.size, header.relr.size):
        entry = _unpack(header.relr, data, pos)[0]
        if entry & 1 == 0:
            offsets.add(entry)
            base = entry + word
        else:
            bits = entry >> 1
            for i in range(bits_per_entry):
                if bits & (1 << i) != 0:
                    offsets.add(base + i * word)
            base += bits_per_entry * word
    return offsets


def _holes(
    section: _Section, relocs: set[int], relro: tuple[int, int] | None, word: int
) -> list[tuple[int, int]]:
    """Byte ranges inside ``section`` that must not be encrypted, merged and sorted."""
    start = section.addr
    end = section.addr + section.size
    raw: list[tuple[int, int]] = [
        (off, min(off + word, end)) for off in relocs if start <= off < end
    ]
    if relro is not None:
        lo = max(start, relro[0])
        hi = min(end, relro[1])
        if lo < hi:
            raw.append((lo, hi))
    if not raw:
        return []
    raw.sort()
    merged: list[tuple[int, int]] = [raw[0]]
    for lo, hi in raw[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi:
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


def _regions_for(
    section: _Section, holes: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """The ``[a, b)`` vaddr sub-ranges of ``section`` left after removing ``holes``."""
    cursor = section.addr
    end = section.addr + section.size
    out: list[tuple[int, int]] = []
    for lo, hi in holes:
        if lo > cursor:
            out.append((cursor, lo))
        cursor = max(cursor, hi)
    if cursor < end:
        out.append((cursor, end))
    return out


def _chacha20(data: bytes | bytearray, key: bytes, nonce: bytes) -> bytes:
    """Applies ChaCha20 to ``data`` (encrypt and decrypt are the same operation)."""
    encryptor = ciphers.Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _derive_key(ikm: bytes, salt: bytes) -> bytes:
    """Derives the 32-byte ChaCha20 content key with HKDF-SHA256, matching the bootstrap's kdf_blob."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=b"")
    return hkdf.derive(ikm)


def _stubcode_salt(
    data: bytes | bytearray, sections: list[_Section], relocs: set[int]
) -> bytes:
    """The HKDF salt: SHA-256 of the clear ``.stubcode`` bytes; the bootstrap hashes the same section at load."""
    stub = _find_section(sections, STUBCODE_SECTION)
    start = stub.addr
    end = stub.addr + stub.size
    if any(start <= off < end for off in relocs):
        raise errors.InvalidRuntimeError(
            "a dynamic relocation patches .stubcode; the bootstrap self-hash would not match at runtime"
        )
    return hashlib.sha256(data[stub.offset : stub.offset + stub.size]).digest()


def _section_at(sections: list[_Section], vaddr: int) -> _Section:
    """Returns the section whose address range contains ``vaddr``."""
    for section in sections:
        if section.size > 0 and section.addr <= vaddr < section.addr + section.size:
            return section
    raise errors.InvalidRuntimeError(f"no section contains vaddr {vaddr:#x}")


def _write_meta(
    data: bytearray,
    meta: _Section,
    stub: _Section,
    text: _Section | None,
    plaintext_text: bytes,
    ikm: bytes,
    regions: list[_Region],
) -> None:
    """Writes the metadata header, the expected plaintext ``.text`` digest and the region table into the ``.packmeta``
    section.

    The digest is the SHA-256 of the plaintext ``.text`` section: the bootstrap verifies the decrypted ``.text``
    against it (the ChaCha20 encryption carries no MAC of its own). The caller passes the section's plaintext,
    because ``data`` already holds the ciphertext by the time this runs.
    """
    words = [int.from_bytes(ikm[4 * i : 4 * i + 4], "little") for i in range(IKM_WORDS)]
    text_addr = text.addr if text is not None else 0
    text_size = text.size if text is not None else 0
    digest = hashlib.sha256(plaintext_text).digest()
    _META_HEADER.pack_into(
        data,
        meta.offset,
        1,  # packed
        words[0],
        len(regions),  # region_count
        words[1],
        meta.addr,  # meta_vaddr
        words[2],
        stub.addr,  # stubcode_vaddr
        words[3],
        stub.size,  # stubcode_size
        words[4],
        words[5],
        text_addr,  # text_vaddr
        words[6],
        words[7],
        text_size,  # text_size
    )
    _META_TEXT_DIGEST.pack_into(data, meta.offset + _META_HEADER.size, digest)
    for index, region in enumerate(regions):
        _REGION.pack_into(
            data,
            meta.offset
            + _META_HEADER.size
            + _META_TEXT_DIGEST.size
            + index * _REGION.size,
            region.vaddr,
            region.size,
            region.is_code,
            0,
            region.nonce,
        )


def _scrub_section_names(data: bytearray, header: _ElfHeader) -> None:
    """Renames the telltale bootstrap sections in place, by editing the section-header string table."""
    shstr = _unpack(
        header.shdr, data, header.shoff + header.shstrndx * header.shentsize
    )
    shstr_offset = shstr[4]
    for index in range(header.shnum):
        fields = _unpack(header.shdr, data, header.shoff + index * header.shentsize)
        start = shstr_offset + fields[0]
        end = _string_end(data, start)
        name = data[start:end].decode("ascii", errors="replace")
        replacement = SECTION_RENAMES.get(name)
        if replacement is None:
            continue
        new = replacement.encode("ascii")
        if len(new) > end - start:
            raise errors.InvalidRuntimeError(
                f"replacement {replacement!r} longer than {name!r}"
            )
        data[start : start + len(new)] = new
        for pos in range(start + len(new), end):
            data[pos] = 0


def _neutralise_soname(
    data: bytearray, header: _ElfHeader, sections: list[_Section]
) -> None:
    """Overwrites DT_SONAME's string in .dynstr with a neutral name, when the library has one."""
    try:
        dynamic = _find_section(sections, ".dynamic")
        dynstr = _find_section(sections, ".dynstr")
    except errors.InvalidRuntimeError:
        return
    soname_str: int | None = None
    for pos in range(dynamic.offset, dynamic.offset + dynamic.size, header.dyn.size):
        tag, value = _unpack(header.dyn, data, pos)
        if tag == _DT_SONAME:
            soname_str = value
        elif tag == _DT_NULL:
            break
    if soname_str is None:
        return
    # DT_SONAME is an offset into the dynamic string table, which is .dynstr.
    start = dynstr.offset + soname_str
    end = _string_end(data, start)
    if len(NEUTRAL_SONAME) > end - start:
        return
    data[start : start + len(NEUTRAL_SONAME)] = NEUTRAL_SONAME
    for pos in range(start + len(NEUTRAL_SONAME), end):
        data[pos] = 0


def encrypt_library(library: bytes) -> bytes:
    """Encrypts a runtime library in place for load-time self-decryption.

    Args:
        library: The content of a ``librasp.so`` built with the self-decrypt bootstrap.

    Returns:
        The library with its code and read-only data encrypted, the metadata written, the bootstrap sections renamed and
        the soname neutralised. Its size does not change.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, has no ``.packmeta``/``.stubcode`` section, is already
            packed, produces too many regions, or has a relocation inside ``.stubcode``.
    """
    data = bytearray(library)
    header = _read_header(data)
    sections = _read_sections(data, header)
    meta = _find_section(sections, META_SECTION)
    stub = _find_section(sections, STUBCODE_SECTION)

    if _unpack(_PACKED_FLAG, data, meta.offset)[0] != 0:
        raise errors.InvalidRuntimeError("the runtime library is already packed")

    relocs = _reloc_offsets(data, sections, header)
    relro = _relro_range(data, header)
    salt = _stubcode_salt(data, sections, relocs)
    ikm = os.urandom(IKM_LEN)
    key = _derive_key(ikm, salt)

    regions: list[_Region] = []
    for name in ENCRYPT_SECTIONS:
        try:
            section = _find_section(sections, name)
        except errors.InvalidRuntimeError:
            continue
        if section.size == 0:
            continue
        is_code = 1 if name == ".text" else 0
        for lo, hi in _regions_for(
            section, _holes(section, relocs, relro, header.word)
        ):
            nonce = b"\x00\x00\x00\x00" + os.urandom(NONCE_LEN - 4)
            file_off = section.offset + (lo - section.addr)
            plaintext = bytes(data[file_off : file_off + (hi - lo)])
            data[file_off : file_off + (hi - lo)] = _chacha20(plaintext, key, nonce)
            regions.append(
                _Region(vaddr=lo, size=hi - lo, is_code=is_code, nonce=nonce)
            )

    if len(regions) > MAX_REGIONS:
        raise errors.InvalidRuntimeError(
            f"{len(regions)} regions exceeds the bootstrap's maximum of {MAX_REGIONS}"
        )
    if meta.size < (
        _META_HEADER.size + _META_TEXT_DIGEST.size + len(regions) * _REGION.size
    ):
        raise errors.InvalidRuntimeError(
            "the .packmeta section is too small for the digest and the region table"
        )

    text = next((section for section in sections if section.name == ".text"), None)
    plaintext_text = (
        library[text.offset : text.offset + text.size] if text is not None else b""
    )
    _write_meta(data, meta, stub, text, plaintext_text, ikm, regions)
    _scrub_section_names(data, header)
    _neutralise_soname(data, header, sections)
    return bytes(data)


def packed_text_digest(library: bytes) -> bytes | None:
    """The plaintext `.text` digest a packed runtime library records, or None when the library is not one."""
    try:
        header = _read_header(library)
        sections = _read_sections(library, header)
        meta = _shipped_section(sections, META_SECTION)
        if _unpack(_PACKED_FLAG, library, meta.offset)[0] != 1:
            return None
        return bytes(
            _unpack(_META_TEXT_DIGEST, library, meta.offset + _META_HEADER.size)[0]
        )
    except errors.InvalidRuntimeError:
        return None


def decrypt_range(library: bytes, offset: int, size: int) -> bytes:
    """Decrypts `size` bytes at file offset `offset` of a packed runtime library.

    Raises:
        InvalidRuntimeError: The library is not a packed runtime library, or the bytes are not inside one encrypted
            region.
    """
    header = _read_header(library)
    sections = _read_sections(library, header)
    meta = _shipped_section(sections, META_SECTION)
    fields = _unpack(_META_HEADER, library, meta.offset)
    if fields[0] != 1:
        raise errors.InvalidRuntimeError("the runtime library is not packed")
    stub = _shipped_section(sections, STUBCODE_SECTION)
    ikm = b"".join(fields[index].to_bytes(4, "little") for index in _IKM_FIELDS)
    key = _derive_key(
        ikm, hashlib.sha256(library[stub.offset : stub.offset + stub.size]).digest()
    )
    holder = _section_holding(sections, offset, size)
    vaddr = holder.addr + (offset - holder.offset)
    table = meta.offset + _META_HEADER.size + _META_TEXT_DIGEST.size
    for index in range(min(fields[2], MAX_REGIONS)):
        start, length, _code, _zero, nonce = _unpack(
            _REGION, library, table + index * _REGION.size
        )
        if start <= vaddr and vaddr + size <= start + length:
            region_offset = holder.offset + (start - holder.addr)
            before = vaddr - start
            plaintext = _chacha20(
                library[region_offset : region_offset + before + size], key, nonce
            )
            return plaintext[before:]
    raise errors.InvalidRuntimeError(
        "the bytes are not inside one encrypted region of the runtime library"
    )


def _shipped_section(sections: list[_Section], name: str) -> _Section:
    """Returns the section under its shipped name, or under its build name in a library that kept it."""
    shipped = SECTION_RENAMES.get(name, name)
    for section in sections:
        if section.name in (shipped, name):
            return section
    raise errors.InvalidRuntimeError(f"the runtime library has no {name} section")


def _section_holding(sections: list[_Section], offset: int, size: int) -> _Section:
    """Returns the section whose file bytes hold `size` bytes at `offset`."""
    for section in sections:
        if (
            section.type != _SHT_NOBITS
            and section.offset <= offset
            and offset + size <= section.offset + section.size
        ):
            return section
    raise errors.InvalidRuntimeError(
        f"no section of the runtime library holds the bytes at {offset:#x}"
    )
