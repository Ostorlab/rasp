"""Minimal ELF64 section reader — just enough to locate the code/read-only regions of a `.so`.

The integrity root (design §8) must be computed over the *same bytes* the device hashes at runtime. The
device hashes byte ranges of its own on-disk `.so`; this module extracts those ranges (`.text`, `.rodata`) by
their file offset and size from the ELF section headers, so the build-time root and the runtime root are
taken over identical inputs.

Scope: 64-bit, little-endian ELF (Android `arm64-v8a` and `x86_64`), which is all the project targets. Other
classes/encodings raise `ElfError`. Standard library only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1


class ElfError(ValueError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    offset: int  # file offset of the section's bytes (sh_offset)
    size: int    # section size in the file (sh_size)
    type: int    # sh_type
    flags: int   # sh_flags


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def read_sections(data: bytes) -> list[Section]:
    """Parse the section headers of a 64-bit little-endian ELF image and return its sections."""
    if len(data) < 64 or data[:4] != ELF_MAGIC:
        raise ElfError("not an ELF file")
    if data[4] != ELFCLASS64:
        raise ElfError("only ELF64 is supported")
    if data[5] != ELFDATA2LSB:
        raise ElfError("only little-endian ELF is supported")

    # ELF64 header fields we need.
    e_shoff = _u64(data, 0x28)
    e_shentsize = _u16(data, 0x3A)
    e_shnum = _u16(data, 0x3C)
    e_shstrndx = _u16(data, 0x3E)
    if e_shoff == 0 or e_shnum == 0:
        raise ElfError("no section headers")
    if e_shoff + e_shnum * e_shentsize > len(data):
        raise ElfError("section headers out of range")

    def entry(i: int) -> tuple[int, int, int, int, int]:
        base = e_shoff + i * e_shentsize
        sh_name = _u32(data, base + 0)
        sh_type = _u32(data, base + 4)
        sh_flags = _u64(data, base + 8)
        sh_offset = _u64(data, base + 24)
        sh_size = _u64(data, base + 32)
        return sh_name, sh_type, sh_flags, sh_offset, sh_size

    if e_shstrndx >= e_shnum:
        raise ElfError("bad section-name string table index")
    _, _, _, str_off, str_size = entry(e_shstrndx)
    strtab = data[str_off : str_off + str_size]

    def name_at(pos: int) -> str:
        end = strtab.find(b"\x00", pos)
        return strtab[pos : end if end >= 0 else None].decode("utf-8", "replace")

    sections: list[Section] = []
    for i in range(e_shnum):
        sh_name, sh_type, sh_flags, sh_offset, sh_size = entry(i)
        sections.append(Section(name_at(sh_name), sh_offset, sh_size, sh_type, sh_flags))
    return sections


def sections_by_name(data: bytes, names: tuple[str, ...]) -> list[Section]:
    """Return the sections matching `names`, in the order of `names` (missing names are skipped)."""
    found = {s.name: s for s in read_sections(data)}
    return [found[n] for n in names if n in found]


# ELF constants used to pick the immutable code/read-only regions.
SHT_PROGBITS = 1
SHF_WRITE = 0x1
SHF_ALLOC = 0x2


def integrity_sections(data: bytes) -> list[Section]:
    """The code and read-only-data sections to hash for the integrity root, sorted by file offset.

    Selects allocatable, non-writable ``PROGBITS`` sections — the executable code (``.text``, ``.init``,
    ``.plt``, …) and the read-only constants (``.rodata`` and its merge variants). Writable sections
    (``.data``, ``.got``, ``.bss``) are excluded: they change at load/run time. Because the root is taken over
    the *file* bytes at these offsets, load-time relocations do not affect it, so the build-time and device
    roots agree. The selection is by semantics, not fixed names, so it is stable across toolchains.
    """
    picked = [
        s
        for s in read_sections(data)
        if s.type == SHT_PROGBITS
        and (s.flags & SHF_ALLOC) != 0
        and (s.flags & SHF_WRITE) == 0
        and s.size > 0
    ]
    return sorted(picked, key=lambda s: s.offset)
