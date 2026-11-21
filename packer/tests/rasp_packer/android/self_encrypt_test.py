"""Tests of encrypting the runtime library at rest for its load-time self-decrypt bootstrap.

A stand-in runtime library, built by ``data/self_encrypt/make.sh``, carries the sections a real linker makes. Small ELF
files built here carry the cases a linker does not make on demand: relocations placed at chosen addresses, a relocation
inside ``.stubcode``, too many regions, and tables that reach outside the file.
"""

import collections.abc
import dataclasses
import hashlib
import pathlib
import re
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rasp_packer import errors
from rasp_packer.android import self_encrypt

_LIBRARY = (
    pathlib.Path(__file__).parents[1] / "data" / "self_encrypt" / "librasp.so"
).read_bytes()

# The layout of rasp::android::selfdecrypt::Meta (runtime/android/src/selfdecrypt/meta.h), whose static_asserts check
# the same numbers on the runtime's side.
_PACKED_OFFSET = 0
_IKM_WORD_OFFSETS = (4, 12, 20, 28, 36, 40, 48, 52)
_REGION_COUNT_OFFSET = 8
_META_VADDR_OFFSET = 16
_STUBCODE_VADDR_OFFSET = 24
_STUBCODE_SIZE_OFFSET = 32
_TEXT_VADDR_OFFSET = 44
_TEXT_SIZE_OFFSET = 56
_TEXT_DIGEST_OFFSET = 60
_REGIONS_OFFSET = 92
_REGION_SIZE = 32
_META_SIZE = 2140

_WORD = struct.Struct("<I")
_REGION = struct.Struct("<IIII16s")

_SHT_PROGBITS = 1
_SHT_STRTAB = 3
_SHT_RELA = 4
_SHT_DYNAMIC = 6
_SHT_REL = 9
_SHT_RELR = 19
_PT_GNU_RELRO = 0x6474E552
_DT_SONAME = 14


@dataclasses.dataclass(frozen=True)
class _Section:
    """A section of a library, read back from its bytes."""

    name: str
    addr: int
    offset: int
    size: int


@dataclasses.dataclass(frozen=True)
class _Region:
    """A region the metadata records."""

    vaddr: int
    size: int
    is_code: int
    nonce: bytes


def _sections(library: bytes) -> dict[str, _Section]:
    """The sections of ``library``, by name."""
    is64 = library[4] == 2
    if is64:
        shoff = struct.unpack_from("<Q", library, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", library, 58)
        shdr_fmt = "<IIQQQQIIQQ"
    else:
        shoff = struct.unpack_from("<I", library, 32)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", library, 46)
        shdr_fmt = "<IIIIIIIIII"
    headers = [
        struct.unpack_from(shdr_fmt, library, shoff + index * shentsize)
        for index in range(shnum)
    ]
    names = headers[shstrndx][4]
    sections: dict[str, _Section] = {}
    for name, _type, _flags, addr, offset, size, *_ in headers:
        start = names + name
        text = library[start : library.index(b"\x00", start)].decode()
        sections[text] = _Section(name=text, addr=addr, offset=offset, size=size)
    return sections


def _bytes_of(library: bytes, section: _Section) -> bytes:
    """The bytes ``section`` holds in ``library``."""
    return library[section.offset : section.offset + section.size]


def _meta(encrypted: bytes) -> bytes:
    """The metadata the encryption wrote, from the section that was ``.packmeta``."""
    return _bytes_of(encrypted, _sections(encrypted)[".data.rel"])


def _word(meta: bytes, offset: int) -> int:
    """The 32-bit little-endian word at ``offset`` of the metadata."""
    return int(_WORD.unpack_from(meta, offset)[0])


def _regions(meta: bytes) -> list[_Region]:
    """The regions the metadata records."""
    regions: list[_Region] = []
    for index in range(_word(meta, _REGION_COUNT_OFFSET)):
        vaddr, size, is_code, _reserved, nonce = _REGION.unpack_from(
            meta, _REGIONS_OFFSET + index * _REGION_SIZE
        )
        regions.append(_Region(vaddr=vaddr, size=size, is_code=is_code, nonce=nonce))
    return regions


def _content_key(encrypted: bytes) -> bytes:
    """The content key the bootstrap derives: HKDF-SHA256 of the scattered IKM words, salted with ``.stubcode``'s hash."""
    meta = _meta(encrypted)
    ikm = b"".join(_WORD.pack(_word(meta, offset)) for offset in _IKM_WORD_OFFSETS)
    stubcode = _sections(encrypted)[".text.hot"]
    salt = hashlib.sha256(_bytes_of(encrypted, stubcode)).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"").derive(ikm)


def _decrypted(encrypted: bytes) -> bytes:
    """``encrypted`` with every region the metadata records decrypted, the way the bootstrap decrypts them."""
    key = _content_key(encrypted)
    data = bytearray(encrypted)
    sections = list(_sections(encrypted).values())
    for region in _regions(_meta(encrypted)):
        section = next(
            s
            for s in sections
            if s.size > 0 and s.addr <= region.vaddr < s.addr + s.size
        )
        offset = section.offset + region.vaddr - section.addr
        cipher = Cipher(algorithms.ChaCha20(key, region.nonce), mode=None)
        data[offset : offset + region.size] = cipher.decryptor().update(
            bytes(data[offset : offset + region.size])
        )
    return bytes(data)


def _restored(encrypted: bytes, original: bytes) -> bytes:
    """``encrypted`` decrypted, with the bytes the encryption rewrites on purpose put back from ``original``: the
    metadata, the section names and the soname."""
    restored = bytearray(_decrypted(encrypted))
    for name in (".packmeta", ".shstrtab", ".dynstr"):
        section = _sections(original)[name]
        restored[section.offset : section.offset + section.size] = _bytes_of(
            original, section
        )
    return bytes(restored)


@dataclasses.dataclass(frozen=True)
class _Spec:
    """A section of a small ELF file to build: its name, its bytes, and its type."""

    name: str
    content: bytes | collections.abc.Callable[[dict[str, int]], bytes]
    type: int = _SHT_PROGBITS
    entsize: int = 0


def _elf(
    specs: collections.abc.Sequence[_Spec], relro: str | None = None, bits: int = 64
) -> tuple[bytes, dict[str, int]]:
    """A little-endian ELF shared object of the given class holding ``specs``, each section at an address equal to its
    file offset.

    A spec's content can be a function of the addresses of the sections before it, to point relocations at them.
    ``relro`` names a section a PT_GNU_RELRO segment covers. Returns the file and the address of each section.
    """
    is64 = bits == 64
    ehsize, phentsize, shentsize = (64, 56, 64) if is64 else (52, 32, 40)
    shdr_fmt = "<IIQQQQIIQQ" if is64 else "<IIIIIIIIII"
    program_headers = 1 if relro is not None else 0
    body = bytearray(ehsize + phentsize * program_headers)
    addresses: dict[str, int] = {}
    placed: list[tuple[_Spec, int, int]] = []
    for spec in specs:
        body += bytes(-len(body) % 16)
        addresses[spec.name] = len(body)
        content = spec.content(addresses) if callable(spec.content) else spec.content
        placed.append((spec, len(body), len(content)))
        body += content
    names = bytearray(b"\x00")
    name_offsets: list[int] = []
    for spec, _offset, _size in placed:
        name_offsets.append(len(names))
        names += spec.name.encode() + b"\x00"
    shstrtab_name = len(names)
    names += b".shstrtab\x00"
    shstrtab_offset = len(body)
    body += names
    body += bytes(-len(body) % 8)
    shoff = len(body)
    body += bytes(shentsize)
    for (spec, offset, size), name in zip(placed, name_offsets, strict=True):
        body += struct.pack(
            shdr_fmt, name, spec.type, 2, offset, offset, size, 0, 0, 8, spec.entsize
        )
    body += struct.pack(
        shdr_fmt,
        shstrtab_name,
        _SHT_STRTAB,
        0,
        0,
        shstrtab_offset,
        len(names),
        0,
        0,
        1,
        0,
    )
    shnum = len(placed) + 2
    elf_class = 2 if is64 else 1
    machine = 183 if is64 else 40
    body[0:16] = b"\x7fELF" + bytes([elf_class]) + b"\x01\x01" + bytes(9)
    header_fmt = "<HHIQQQIHHHHHH" if is64 else "<HHIIIIIHHHHHH"
    struct.pack_into(
        header_fmt,
        body,
        16,
        3,
        machine,
        1,
        0,
        ehsize,
        shoff,
        0,
        ehsize,
        phentsize,
        program_headers,
        shentsize,
        shnum,
        shnum - 1,
    )
    if relro is not None:
        size = next(size for spec, _offset, size in placed if spec.name == relro)
        addr = addresses[relro]
        if is64:
            struct.pack_into(
                "<IIQQQQQQ",
                body,
                ehsize,
                _PT_GNU_RELRO,
                4,
                addr,
                addr,
                addr,
                size,
                size,
                1,
            )
        else:
            struct.pack_into(
                "<IIIIIIII",
                body,
                ehsize,
                _PT_GNU_RELRO,
                addr,
                addr,
                addr,
                size,
                size,
                4,
                1,
            )
    return bytes(body), addresses


def _rela(
    *targets: str | tuple[str, int],
) -> collections.abc.Callable[[dict[str, int]], bytes]:
    """A RELA table whose entries patch the given sections, at their start or at an offset into them."""

    def build(addresses: dict[str, int]) -> bytes:
        return b"".join(
            struct.pack("<QQq", _address(addresses, target), 1027, 0)
            for target in targets
        )

    return build


def _rel(
    *targets: str | tuple[str, int], bits: int = 64
) -> collections.abc.Callable[[dict[str, int]], bytes]:
    """A REL table whose entries patch the given sections, at their start or at an offset into them."""
    fmt = "<QQ" if bits == 64 else "<II"

    def build(addresses: dict[str, int]) -> bytes:
        return b"".join(
            struct.pack(fmt, _address(addresses, target), 1027) for target in targets
        )

    return build


def _address(addresses: dict[str, int], target: str | tuple[str, int]) -> int:
    """The address a relocation target names: a section's start, or an offset into a section."""
    if isinstance(target, str):
        return addresses[target]
    name, offset = target
    return addresses[name] + offset


def _library(
    *extra: _Spec,
    rodata: bytes = bytes(range(256)),
    packmeta_size: int = _META_SIZE,
    relro: str | None = None,
    soname: bool = True,
    bits: int = 64,
) -> tuple[bytes, dict[str, int]]:
    """A small library with the sections the encryption needs, followed by ``extra``."""
    specs = [
        _Spec(".packmeta", bytes(packmeta_size)),
        _Spec(".stubcode", b"\xd5\x03\x20\x1f" * 4),
        _Spec(".stubrodata", b"stub constants\x00"),
        _Spec(".text", bytes((index * 7) & 0xFF for index in range(96))),
        _Spec(".rodata", rodata),
        _Spec(".eh_frame", bytes(range(48))),
    ]
    if soname:
        dyn = (
            struct.pack("<qQqQ", _DT_SONAME, 1, 0, 0)
            if bits == 64
            else struct.pack("<iIiI", _DT_SONAME, 1, 0, 0)
        )
        specs.append(_Spec(".dynstr", b"\x00librasp.so\x00", _SHT_STRTAB))
        specs.append(_Spec(".dynamic", dyn, _SHT_DYNAMIC, 16 if bits == 64 else 8))
    return _elf([*specs, *extra], relro, bits)


def _rodata_regions(
    encrypted: bytes, addresses: dict[str, int], size: int
) -> list[tuple[int, int]]:
    """The ``[start, end)`` offsets into ``.rodata`` of the regions the metadata records there."""
    start = addresses[".rodata"]
    return [
        (region.vaddr - start, region.vaddr - start + region.size)
        for region in _regions(_meta(encrypted))
        if start <= region.vaddr < start + size
    ]


def testEncryptLibrary_whenGivenTheRuntimeStandIn_keepsItsSize() -> None:
    assert len(self_encrypt.encrypt_library(_LIBRARY)) == len(_LIBRARY)


def testEncryptLibrary_whenGivenTheRuntimeStandIn_encryptsItsCodeAndReadOnlyData() -> (
    None
):
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    before = _sections(_LIBRARY)
    after = _sections(encrypted)
    for name in (".text", ".rodata", ".eh_frame", ".eh_frame_hdr"):
        assert _bytes_of(encrypted, after[name]) != _bytes_of(_LIBRARY, before[name]), (
            name
        )


def testEncryptLibrary_whenGivenTheRuntimeStandIn_decryptsBackToEveryOriginalByte() -> (
    None
):
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    assert _restored(encrypted, _LIBRARY) == _LIBRARY


def testEncryptLibrary_whenTheLibraryIsElf32_encryptsAndDecryptsBackToTheOriginal() -> (
    None
):
    library, _addresses = _library(bits=32)

    encrypted = self_encrypt.encrypt_library(library)

    after = _sections(encrypted)
    before = _sections(library)
    assert _bytes_of(encrypted, after[".text"]) != _bytes_of(library, before[".text"])
    assert len(encrypted) == len(library)
    assert _restored(encrypted, library) == library


def testEncryptLibrary_whenAnElf32RelRelocationPatchesTheReadOnlyData_leavesItsWordClear() -> (
    None
):
    library, addresses = _library(
        _Spec(".rel.dyn", _rel((".rodata", 128), bits=32), _SHT_REL, 8), bits=32
    )

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == [(0, 128), (132, 256)]


def testEncryptLibrary_whenGivenTheRuntimeStandIn_leavesTheBootstrapAndTheRelocatedDataClear() -> (
    None
):
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    before = _sections(_LIBRARY)
    after = _sections(encrypted)
    assert _bytes_of(encrypted, after[".text.hot"]) == _bytes_of(
        _LIBRARY, before[".stubcode"]
    )
    for name in (".data.rel.ro", ".dynamic", ".got"):
        assert _bytes_of(encrypted, after[name]) == _bytes_of(_LIBRARY, before[name]), (
            name
        )


def testEncryptLibrary_whenGivenTheRuntimeStandIn_recordsTheTextAsTheOnlyCodeRegion() -> (
    None
):
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    text = _sections(_LIBRARY)[".text"]
    code = [region for region in _regions(_meta(encrypted)) if region.is_code == 1]
    assert [(region.vaddr, region.size) for region in code] == [(text.addr, text.size)]


def testEncryptLibrary_whenGivenTheRuntimeStandIn_writesThePlaintextTextDigest() -> (
    None
):
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    meta = _meta(encrypted)
    text = _sections(_LIBRARY)[".text"]
    digest = meta[_TEXT_DIGEST_OFFSET : _TEXT_DIGEST_OFFSET + 32]
    assert digest == hashlib.sha256(_bytes_of(_LIBRARY, text)).digest()


def testPackedTextDigest_whenTheLibraryIsPacked_returnsThePlaintextTextDigest() -> None:
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    text = _sections(_LIBRARY)[".text"]
    assert (
        self_encrypt.packed_text_digest(encrypted)
        == hashlib.sha256(_bytes_of(_LIBRARY, text)).digest()
    )


def testPackedTextDigest_whenTheLibraryIsNotPacked_returnsNone() -> None:
    assert self_encrypt.packed_text_digest(_LIBRARY) is None


def testPackedTextDigest_whenNotAnElfFile_returnsNone() -> None:
    assert self_encrypt.packed_text_digest(b"not a library") is None


def testDecryptRange_whenGivenARangeInTheText_returnsItsPlaintext() -> None:
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    text = _sections(_LIBRARY)[".text"]
    offset = text.offset + 16
    assert (
        self_encrypt.decrypt_range(encrypted, offset, 32)
        == _bytes_of(_LIBRARY, text)[16:48]
    )


def testDecryptRange_whenTheBytesAreNotInAnEncryptedRegion_raisesInvalidRuntimeError() -> (
    None
):
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    dynstr = _sections(encrypted)[".dynstr"]
    with pytest.raises(errors.InvalidRuntimeError, match="not inside one encrypted"):
        self_encrypt.decrypt_range(encrypted, dynstr.offset, 16)


def testDecryptRange_whenTheLibraryIsNotPacked_raisesInvalidRuntimeError() -> None:
    text = _sections(_LIBRARY)[".text"]
    with pytest.raises(errors.InvalidRuntimeError, match="not packed"):
        self_encrypt.decrypt_range(_LIBRARY, text.offset, 16)


def testEncryptLibrary_whenGivenTheRuntimeStandIn_renamesTheBootstrapSectionsAndTheSoname() -> (
    None
):
    encrypted = self_encrypt.encrypt_library(_LIBRARY)

    names = set(_sections(encrypted))
    assert {".stubcode", ".packmeta"} & names == set()
    assert {".text.hot", ".data.rel"} <= names
    assert b"librasp.so" not in encrypted
    assert b"libjni.so" in _bytes_of(encrypted, _sections(encrypted)[".dynstr"])


def testEncryptLibrary_whenCalledTwice_usesFreshKeyMaterialAndNonces() -> None:
    first = self_encrypt.encrypt_library(_LIBRARY)
    second = self_encrypt.encrypt_library(_LIBRARY)

    assert first != second
    assert _content_key(first) != _content_key(second)
    assert _restored(first, _LIBRARY) == _restored(second, _LIBRARY) == _LIBRARY


def testEncryptLibrary_whenTheLibraryIsAlreadyPacked_raisesInvalidRuntimeError() -> (
    None
):
    packed = bytearray(_LIBRARY)
    meta = _sections(_LIBRARY)[".packmeta"]
    _WORD.pack_into(packed, meta.offset + _PACKED_OFFSET, 1)

    with pytest.raises(errors.InvalidRuntimeError, match="already packed"):
        self_encrypt.encrypt_library(bytes(packed))


def testEncryptLibrary_whenGivenASmallLibrary_writesTheMetadataAtTheOffsetsOfTheRuntimesStruct() -> (
    None
):
    library, addresses = _library()

    encrypted = self_encrypt.encrypt_library(library)

    meta = _meta(encrypted)
    assert _word(meta, _PACKED_OFFSET) == 1
    assert _word(meta, _META_VADDR_OFFSET) == addresses[".packmeta"]
    assert _word(meta, _STUBCODE_VADDR_OFFSET) == addresses[".stubcode"]
    assert _word(meta, _STUBCODE_SIZE_OFFSET) == 16
    assert _word(meta, _TEXT_VADDR_OFFSET) == addresses[".text"]
    assert _word(meta, _TEXT_SIZE_OFFSET) == 96
    assert [
        (region.vaddr, region.size, region.is_code) for region in _regions(meta)
    ] == [
        (addresses[".text"], 96, 1),
        (addresses[".rodata"], 256, 0),
        (addresses[".eh_frame"], 48, 0),
    ]
    assert all(region.nonce[:4] == bytes(4) for region in _regions(meta))


def testEncryptLibrary_whenGivenASmallLibrary_renamesTheStubReadOnlyData() -> None:
    library, _addresses = _library()

    encrypted = self_encrypt.encrypt_library(library)

    assert ".stubrodata" not in _sections(encrypted)
    assert ".rodata.cst" in _sections(encrypted)


def testEncryptLibrary_whenARelaRelocationPatchesTheReadOnlyData_leavesItsWordClear() -> (
    None
):
    library, addresses = _library(
        _Spec(".rela.dyn", _rela((".rodata", 64)), _SHT_RELA, 24)
    )

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == [(0, 64), (72, 256)]
    start = addresses[".rodata"]
    assert encrypted[start + 64 : start + 72] == library[start + 64 : start + 72]
    assert _decrypted(encrypted)[start : start + 256] == library[start : start + 256]


def testEncryptLibrary_whenARelRelocationPatchesTheReadOnlyData_leavesItsWordClear() -> (
    None
):
    library, addresses = _library(
        _Spec(".rel.dyn", _rel((".rodata", 128)), _SHT_REL, 16)
    )

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == [(0, 128), (136, 256)]


def testEncryptLibrary_whenRelrEntriesPatchTheReadOnlyData_leavesEveryWordTheyNameClear() -> (
    None
):
    def relr(addresses: dict[str, int]) -> bytes:
        start = addresses[".rodata"] + 16
        bitmap = ((1 << 0) | (1 << 2)) << 1 | 1
        return struct.pack("<QQ", start, bitmap)

    library, addresses = _library(_Spec(".relr.dyn", relr, _SHT_RELR, 8))

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == [(0, 16), (32, 40), (48, 256)]


def testEncryptLibrary_whenElf32RelrEntriesPatchTheReadOnlyData_leavesEveryWordTheyNameClear() -> (
    None
):
    def relr(addresses: dict[str, int]) -> bytes:
        start = addresses[".rodata"] + 16
        first = ((1 << 0) | (1 << 2)) << 1 | 1
        second = (1 << 0) << 1 | 1
        return struct.pack("<III", start, first, second)

    library, addresses = _library(_Spec(".relr.dyn", relr, _SHT_RELR, 4), bits=32)

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == [
        (0, 16),
        (24, 28),
        (32, 144),
        (148, 256),
    ]


def testEncryptLibrary_whenRelocationsPatchAdjacentWords_carvesOneHole() -> None:
    library, addresses = _library(
        _Spec(".rela.dyn", _rela((".rodata", 32), (".rodata", 40)), _SHT_RELA, 24)
    )

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == [(0, 32), (48, 256)]


def testEncryptLibrary_whenARelocationPatchesTheLastBytes_endsTheHoleAtTheSection() -> (
    None
):
    library, addresses = _library(
        _Spec(".rela.dyn", _rela((".rodata", 252)), _SHT_RELA, 24)
    )

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == [(0, 252)]


def testEncryptLibrary_whenTheReadOnlyDataIsRelro_leavesItClear() -> None:
    library, addresses = _library(relro=".rodata")

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == []
    start = addresses[".rodata"]
    assert encrypted[start : start + 256] == library[start : start + 256]


def testEncryptLibrary_whenTheReadOnlyDataOfAnElf32LibraryIsRelro_leavesItClear() -> (
    None
):
    library, addresses = _library(relro=".rodata", bits=32)

    encrypted = self_encrypt.encrypt_library(library)

    assert _rodata_regions(encrypted, addresses, 256) == []
    start = addresses[".rodata"]
    assert encrypted[start : start + 256] == library[start : start + 256]


def testEncryptLibrary_whenARelocationPatchesTheStubcode_raisesInvalidRuntimeError() -> (
    None
):
    library, _addresses = _library(
        _Spec(".rela.dyn", _rela((".stubcode", 8)), _SHT_RELA, 24)
    )

    with pytest.raises(errors.InvalidRuntimeError, match=r"patches \.stubcode"):
        self_encrypt.encrypt_library(library)


def testEncryptLibrary_whenTheHolesMakeMoreThan64Regions_raisesInvalidRuntimeError() -> (
    None
):
    targets = [(".rodata", offset) for offset in range(8, 1024, 16)]
    library, _addresses = _library(
        _Spec(".rela.dyn", _rela(*targets), _SHT_RELA, 24), rodata=bytes(1024)
    )

    with pytest.raises(
        errors.InvalidRuntimeError, match="exceeds the bootstrap's maximum of 64"
    ):
        self_encrypt.encrypt_library(library)


def testEncryptLibrary_whenThe64RegionsFit_writesThemAll() -> None:
    targets = [(".rodata", offset) for offset in range(8, 992, 16)]
    library, _addresses = _library(
        _Spec(".rela.dyn", _rela(*targets), _SHT_RELA, 24), rodata=bytes(992)
    )

    encrypted = self_encrypt.encrypt_library(library)

    assert len(_regions(_meta(encrypted))) == 64


def testEncryptLibrary_whenThePackmetaIsTooSmallForTheRegions_raisesInvalidRuntimeError() -> (
    None
):
    library, _addresses = _library(packmeta_size=_REGIONS_OFFSET + 2 * _REGION_SIZE)

    with pytest.raises(errors.InvalidRuntimeError, match="too small"):
        self_encrypt.encrypt_library(library)


def testEncryptLibrary_whenTheLibraryHasNoSoname_leavesItsStringsAsTheyAre() -> None:
    library, _addresses = _library(soname=False)

    encrypted = self_encrypt.encrypt_library(library)

    assert len(_regions(_meta(encrypted))) == 3


@pytest.mark.parametrize("missing", [".packmeta", ".stubcode"])
def testEncryptLibrary_whenABootstrapSectionIsMissing_raisesInvalidRuntimeError(
    missing: str,
) -> None:
    library, _addresses = _elf(
        [
            _Spec(name, bytes(_META_SIZE if name == ".packmeta" else 16))
            for name in (".packmeta", ".stubcode", ".text")
            if name != missing
        ]
    )

    with pytest.raises(
        errors.InvalidRuntimeError, match=re.escape(f"no {missing} section")
    ):
        self_encrypt.encrypt_library(library)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda data: bytes(4) + data[4:], "not an ELF file"),
        (lambda data: data[:4] + b"\x00" + data[5:], "not a little-endian ELF object"),
        (lambda data: data[:5] + b"\x02" + data[6:], "not a little-endian ELF object"),
        (lambda data: data[:32], "not an ELF file"),
    ],
    ids=["no magic", "bad class", "big-endian", "cut inside the header"],
)
def testEncryptLibrary_whenTheFileIsNotALittleEndianElf_raisesInvalidRuntimeError(
    change: collections.abc.Callable[[bytes], bytes], message: str
) -> None:
    library, _addresses = _library()

    with pytest.raises(errors.InvalidRuntimeError, match=message):
        self_encrypt.encrypt_library(change(library))


def testEncryptLibrary_whenTheLibraryHasNoSectionHeaders_raisesInvalidRuntimeError() -> (
    None
):
    library, _addresses = _library()
    data = bytearray(library)
    struct.pack_into("<Q", data, 40, 0)

    with pytest.raises(errors.InvalidRuntimeError, match="no section headers"):
        self_encrypt.encrypt_library(bytes(data))


def _cut_section_headers(library: bytes) -> bytes:
    """``library`` cut in the middle of its section header table."""
    shoff = struct.unpack_from("<Q", library, 40)[0]
    return library[: shoff + 100]


def _bad_shstrndx(library: bytes) -> bytes:
    """``library`` whose section-name table index is past the last section."""
    data = bytearray(library)
    struct.pack_into("<H", data, 62, 200)
    return bytes(data)


def _name_past_the_end(library: bytes) -> bytes:
    """``library`` whose first named section's name starts past the end of the file."""
    data = bytearray(library)
    shoff = struct.unpack_from("<Q", library, 40)[0]
    struct.pack_into("<I", data, shoff + 64, len(library) + 10)
    return bytes(data)


def _section_past_the_end(library: bytes) -> bytes:
    """``library`` whose ``.text`` reaches past the end of the file."""
    data = bytearray(library)
    shoff = struct.unpack_from("<Q", library, 40)[0]
    struct.pack_into("<Q", data, shoff + 4 * 64 + 32, len(library))
    return bytes(data)


@pytest.mark.parametrize(
    "change",
    [_cut_section_headers, _bad_shstrndx, _name_past_the_end, _section_past_the_end],
    ids=[
        "cut section headers",
        "bad name table index",
        "name past the end",
        "section past the end",
    ],
)
def testEncryptLibrary_whenATableReachesOutsideTheFile_raisesInvalidRuntimeError(
    change: collections.abc.Callable[[bytes], bytes],
) -> None:
    library, _addresses = _library()

    with pytest.raises(errors.InvalidRuntimeError, match="truncated or malformed"):
        self_encrypt.encrypt_library(change(library))


def testEncryptLibrary_whenAProgramHeaderReachesOutsideTheFile_raisesInvalidRuntimeError() -> (
    None
):
    library, _addresses = _library(relro=".rodata")
    data = bytearray(library)
    struct.pack_into("<Q", data, 32, len(library))

    with pytest.raises(errors.InvalidRuntimeError, match="truncated or malformed"):
        self_encrypt.encrypt_library(bytes(data))
