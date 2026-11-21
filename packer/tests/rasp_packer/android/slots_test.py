"""Tests of locating, writing and reading the slots of the Android runtime library."""

import random

import pytest

from rasp_packer import errors
from rasp_packer.android import slots
from tests.rasp_packer import conftest

_LIBRARY = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
_PROGRAM = bytes(range(256)) * 2
_DIGEST = bytes(range(64, 96))


def _values(build_id: str = "build-1", checks_mask: int = 32) -> slots.Values:
    return slots.Values(
        build_id=build_id,
        checks_mask=checks_mask,
        program=_PROGRAM,
        text_digest=_DIGEST,
    )


def testLocate_whenGivenARawLibrary_findsEverySlot() -> None:
    layout = slots.locate(_LIBRARY)

    for slot in slots.ALL_SLOTS:
        assert layout.span(slot) == (layout.offset(slot), slot.size)


def testLocate_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        slots.locate(b"not a library")


def testLocate_whenAMarkerIsMissing_raisesInvalidRuntimeError() -> None:
    offset = slots.locate(_LIBRARY).offset(slots.BUILD_ID)
    corrupted = bytearray(_LIBRARY)
    corrupted[offset : offset + len(slots.BUILD_ID.marker)] = bytes(
        len(slots.BUILD_ID.marker)
    )

    with pytest.raises(errors.InvalidRuntimeError, match="no single build slot"):
        slots.locate(bytes(corrupted))


def testLocate_whenAMarkerIsDuplicated_raisesInvalidRuntimeError() -> None:
    layout = slots.locate(_LIBRARY)
    pad_offset = layout.offset(slots.PAD)
    corrupted = bytearray(_LIBRARY)
    corrupted[pad_offset : pad_offset + len(slots.BUILD_ID.marker)] = (
        slots.BUILD_ID.marker
    )

    with pytest.raises(errors.InvalidRuntimeError, match="no single build slot"):
        slots.locate(bytes(corrupted))


def testLocate_whenASlotLiesOutsideItsSection_raisesInvalidRuntimeError() -> None:
    layout = slots.locate(_LIBRARY)
    share_offset = layout.offset(slots.SHARE)
    decoy_offset = layout.offset(slots.DECOYS[2])
    corrupted = bytearray(_LIBRARY)
    # Drop the real .data share marker and plant it inside a .rodata decoy slot.
    corrupted[share_offset : share_offset + len(slots.SHARE.marker)] = bytes(
        len(slots.SHARE.marker)
    )
    planted = decoy_offset + len(slots.DECOYS[2].marker)
    corrupted[planted : planted + len(slots.SHARE.marker)] = slots.SHARE.marker

    with pytest.raises(errors.InvalidRuntimeError, match="share slot is not in its"):
        slots.locate(bytes(corrupted))


def testWrite_whenGivenValues_readsThemBack() -> None:
    layout = slots.locate(_LIBRARY)

    written = slots.write(_LIBRARY, layout, _values(), random.Random(0))

    assert (
        slots.decode_build_id(slots.read(written, layout, slots.BUILD_ID)) == "build-1"
    )
    assert slots.decode_checks_mask(slots.read(written, layout, slots.CHECKS)) == 32
    assert slots.read(written, layout, slots.PROGRAM) == _PROGRAM
    assert slots.read(written, layout, slots.DIGEST) == _DIGEST


def testWrite_whenGivenALibrary_keepsItsSize() -> None:
    layout = slots.locate(_LIBRARY)

    written = slots.write(_LIBRARY, layout, _values(), random.Random(0))

    assert len(written) == len(_LIBRARY)


def testWrite_whenTheBuildIdDoesNotFit_raisesConfigTooLargeError() -> None:
    layout = slots.locate(_LIBRARY)

    with pytest.raises(errors.ConfigTooLargeError):
        slots.write(
            _LIBRARY,
            layout,
            _values(build_id="x" * slots.BUILD_ID.size),
            random.Random(0),
        )


def testWrite_whenTheProgramIsTheWrongSize_raisesValueError() -> None:
    layout = slots.locate(_LIBRARY)
    values = slots.Values(
        build_id="build-1", checks_mask=0, program=bytes(64), text_digest=_DIGEST
    )

    with pytest.raises(ValueError, match="fold program must be"):
        slots.write(_LIBRARY, layout, values, random.Random(0))


def testWriteShare_whenGivenAShare_readsItBackMaskedWithThePad() -> None:
    layout = slots.locate(_LIBRARY)
    written = slots.write(_LIBRARY, layout, _values(), random.Random(0))
    pad = slots.read(written, layout, slots.PAD)
    share = bytes(range(32, 64))

    with_share = slots.write_share(written, layout, share, pad)

    stored = slots.read(with_share, layout, slots.SHARE)
    assert stored != share
    assert slots.mask_share(stored, pad) == share


def testWriteShare_whenTheShareIsTheWrongSize_raisesValueError() -> None:
    layout = slots.locate(_LIBRARY)
    written = slots.write(_LIBRARY, layout, _values(), random.Random(0))
    pad = slots.read(written, layout, slots.PAD)

    with pytest.raises(ValueError, match="32 bytes"):
        slots.write_share(written, layout, bytes(31), pad)


def testMaskShare_whenAppliedTwice_givesTheShareBack() -> None:
    share = bytes(range(32, 64))
    pad = bytes(range(96, 128))

    assert slots.mask_share(slots.mask_share(share, pad), pad) == share


def testRegion_whenGivenAWrittenLibrary_concatenatesTheRegionSlots() -> None:
    layout = slots.locate(_LIBRARY)
    written = slots.write(_LIBRARY, layout, _values(), random.Random(0))

    region = slots.region(written, layout)

    assert len(region) == sum(slot.size for slot in slots.REGION_SLOTS)
    assert region.startswith(slots.read(written, layout, slots.BUILD_ID))
