"""Tests of reading the sections of the Android runtime library that the key schedule digests."""

import io

import lief
import pytest

from rasp_packer import errors
from rasp_packer.android import key_schedule
from rasp_packer.android import runtime_library
from tests.rasp_packer import conftest

_LIBRARY = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()


def testTextRegion_whenGivenALibrary_returnsItsExecutableCode() -> None:
    text = runtime_library.text_region(_LIBRARY)

    assert len(text) > 0


def testTextRegion_whenTheLibraryCodeIsPatched_changes() -> None:
    elf = lief.ELF.parse(io.BytesIO(_LIBRARY))
    assert elf is not None
    section = elf.get_section(runtime_library.TEXT_SECTION)
    assert section is not None
    patched = bytearray(_LIBRARY)
    patched[section.offset] ^= 0x01

    assert runtime_library.text_region(bytes(patched)) != runtime_library.text_region(
        _LIBRARY
    )


def testSectionRegion_whenGivenALibrary_returnsTheNamedSection() -> None:
    region = runtime_library.section_region(_LIBRARY, ".rela.dyn")

    assert len(region) > 0
    assert region != runtime_library.text_region(_LIBRARY)


def testSectionRegion_whenTheLibraryHasNoSection_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match=r"\.no_such_section"):
        runtime_library.section_region(_LIBRARY, ".no_such_section")


def testFoldSections_whenGivenALibrary_returnsTheTableSectionsItHas() -> None:
    sections = runtime_library.fold_sections(_LIBRARY)

    assert ".rela.dyn" in sections
    assert ".text" not in sections
    assert set(sections) <= set(key_schedule.SECTION_NAMES)


def testTextRegion_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.text_region(b"not a library")
