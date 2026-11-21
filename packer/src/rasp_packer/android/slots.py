"""The slots of the Android runtime library, `librasp.so`, that hold the per-app values the packer writes."""

import collections.abc
import dataclasses
import io
import random

import lief

from rasp_packer import errors

MAGIC = b"\x9cRASPSLT"
_ID_SIZE = 8
_MASK_SIZE = 8


@dataclasses.dataclass(frozen=True, slots=True)
class Slot:
    """One slot of the runtime library.

    Attributes:
        id: The name its marker carries after the magic.
        size: Its size, in bytes.
        section: The section the runtime's build places it in.
    """

    id: str
    size: int
    section: str

    @property
    def marker(self) -> bytes:
        """The bytes the slot starts with until the packer writes it."""
        return MAGIC + self.id.encode("ascii").ljust(_ID_SIZE, b"\0")


BUILD_ID = Slot("build", 128, ".rodata")
CHECKS = Slot("checks", 16, ".rodata")
PROGRAM = Slot("program", 512, ".rodata")
DIGEST = Slot("digest", 32, ".rodata")
PAD = Slot("pad", 32, ".rodata")
DECOYS = (
    Slot("decoy0", 32, ".rodata"),
    Slot("decoy1", 32, ".rodata"),
    Slot("decoy2", 32, ".rodata"),
)
# Written after the fold, so it must sit outside every section the fold digests; it is stored masked with the pad.
SHARE = Slot("share", 32, ".data")

# The slots the key schedule's region record digests, in the order it digests them.
REGION_SLOTS = (BUILD_ID, CHECKS, PROGRAM, DIGEST, PAD, *DECOYS)
ALL_SLOTS = (*REGION_SLOTS, SHARE)


@dataclasses.dataclass(frozen=True, slots=True)
class Layout:
    """Where each slot starts in a runtime library's file."""

    offsets: collections.abc.Mapping[str, int]

    def offset(self, slot: Slot) -> int:
        """The slot's file offset."""
        return self.offsets[slot.id]

    def span(self, slot: Slot) -> tuple[int, int]:
        """The slot's file offset and size."""
        return self.offsets[slot.id], slot.size


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Values:
    """The per-app values the packer writes into the slots before the library is encrypted.

    Attributes:
        build_id: The id of the protected build.
        checks_mask: The check groups the app runs, one bit per group in the platform's run order.
        program: The encoded fold program.
        text_digest: The SHA-256 of the library's plaintext `.text`.
    """

    build_id: str
    checks_mask: int
    program: bytes
    text_digest: bytes


def locate(library: bytes) -> Layout:
    """Finds every slot of a runtime library the packer has not written yet.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, a slot's marker is missing or repeated, or a slot lies
            outside its section.
    """
    sections = _file_sections(library)
    offsets: dict[str, int] = {}
    for slot in ALL_SLOTS:
        offset = library.find(slot.marker)
        if offset < 0 or library.find(slot.marker, offset + 1) >= 0:
            raise errors.InvalidRuntimeError(
                f"the runtime library has no single {slot.id} slot"
            )
        if _holds(sections.get(slot.section), offset, slot.size) is False:
            raise errors.InvalidRuntimeError(
                f"the runtime library's {slot.id} slot is not in its {slot.section} section"
            )
        offsets[slot.id] = offset
    return Layout(offsets)


def write(
    library: bytes, layout: Layout, values: Values, generator: random.Random
) -> bytes:
    """Writes the values into the slots, with random bytes over the pad, the decoys and every slot's unused bytes.

    The share slot is left as it is: write_share fills it once the library is encrypted and folded.

    Raises:
        ConfigTooLargeError: The build id and its terminating zero do not fit in their slot.
        ValueError: The program or the digest is not the size of its slot.
    """
    build_id = values.build_id.encode("utf-8")
    if len(build_id) >= BUILD_ID.size:
        raise errors.ConfigTooLargeError(
            f"the build id is {len(build_id)} bytes, and the runtime keeps room for {BUILD_ID.size - 1}"
        )
    if len(values.program) != PROGRAM.size:
        raise ValueError(f"the fold program must be {PROGRAM.size} bytes")
    if len(values.text_digest) != DIGEST.size:
        raise ValueError(f"the text digest must be {DIGEST.size} bytes")
    contents: dict[Slot, bytes] = {
        BUILD_ID: build_id + b"\0",
        CHECKS: values.checks_mask.to_bytes(_MASK_SIZE, "little"),
        PROGRAM: values.program,
        DIGEST: values.text_digest,
        PAD: b"",
        **dict.fromkeys(DECOYS, b""),
    }
    written = bytearray(library)
    for slot, content in contents.items():
        start = layout.offset(slot)
        written[start : start + slot.size] = content + generator.randbytes(
            slot.size - len(content)
        )
    return bytes(written)


def read(library: bytes, layout: Layout, slot: Slot) -> bytes:
    """The bytes of one slot of a library whose slots hold plaintext."""
    start = layout.offset(slot)
    return library[start : start + slot.size]


def region(library: bytes, layout: Layout) -> bytes:
    """The bytes the key schedule's region record digests, from a library whose slots hold plaintext."""
    return b"".join(read(library, layout, slot) for slot in REGION_SLOTS)


def write_share(library: bytes, layout: Layout, share: bytes, pad: bytes) -> bytes:
    """Writes the keystore share, masked with the pad, into the share slot.

    Raises:
        ValueError: The share or the pad is not the size of its slot.
    """
    if len(share) != SHARE.size or len(pad) != PAD.size:
        raise ValueError(
            f"the keystore share and its pad must be {SHARE.size} bytes each"
        )
    start = layout.offset(SHARE)
    written = bytearray(library)
    written[start : start + SHARE.size] = mask_share(share, pad)
    return bytes(written)


def mask_share(share: bytes, pad: bytes) -> bytes:
    """The share masked with the pad; masking twice gives the share back."""
    return bytes(left ^ right for left, right in zip(share, pad, strict=True))


def decode_build_id(slot: bytes) -> str:
    """The build id a build-id slot holds: its bytes up to the first zero byte."""
    return slot.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def decode_checks_mask(slot: bytes) -> int:
    """The checks mask a checks slot holds."""
    return int.from_bytes(slot[:_MASK_SIZE], "little")


def _file_sections(library: bytes) -> dict[str, tuple[int, int]]:
    """The file offset and size of each section that has bytes in the file, by name."""
    elf = lief.ELF.parse(io.BytesIO(library))
    if elf is None:
        raise errors.InvalidRuntimeError("the runtime library is not an ELF file")
    return {
        str(section.name): (section.offset, section.size)
        for section in elf.sections
        if section.type != lief.ELF.Section.TYPE.NOBITS
    }


def _holds(section: tuple[int, int] | None, offset: int, size: int) -> bool:
    """Whether the section's file range holds `size` bytes at `offset`."""
    if section is None:
        return False
    start, length = section
    return start <= offset and offset + size <= start + length
