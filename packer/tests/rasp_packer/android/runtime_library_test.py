"""Tests of writing the runtime's config, fold program and keystore into, and reading them from, the Android runtime library."""

import io

import lief
import pytest

from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.android import key_schedule
from rasp_packer.android import runtime_library
from tests.rasp_packer import conftest

_CONFIG = runtime_config.RuntimeConfig(
    build_id="build-1", checks=("identity",), checks_mask=32
)
_LIBRARY = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
_SHARE = bytes(range(32, 64))
_DIGEST = bytes(range(64, 96))
_PROGRAM = bytes(key_schedule.PROGRAM_SIZE)


def _configured() -> bytes:
    """Returns the fixture library with its config written."""
    return runtime_library.write_config(_LIBRARY, _CONFIG)


def testReadConfig_whenThePackerWroteNoConfig_readsTheRuntimesEmptyConfig() -> None:
    assert runtime_library.read_config(_LIBRARY) == b"{}"


def testWriteConfig_whenGivenALibrary_writesTheConfigIntoItsSection() -> None:
    library = runtime_library.write_config(_LIBRARY, _CONFIG)

    assert runtime_library.read_config(library) == _CONFIG.to_json()


def testWriteConfig_whenGivenALibrary_zeroesTheProgramAndKeystoreSlots() -> None:
    library = runtime_library.write_config(_LIBRARY, _CONFIG)

    assert runtime_library.program(library) == bytes(key_schedule.PROGRAM_SIZE)
    assert runtime_library.keystore(library) == bytes(key_schedule.KEY_SIZE)


def testWriteConfig_whenGivenALibrary_changesOnlyTheConfigSection() -> None:
    library = runtime_library.write_config(_LIBRARY, _CONFIG)

    changed = [
        index
        for index, (old, new) in enumerate(zip(_LIBRARY, library, strict=True))
        if old != new
    ]
    assert len(library) == len(_LIBRARY)
    assert len(changed) > 0
    assert max(changed) - min(changed) < 4096


def testWriteConfig_whenTheConfigLeavesNoProgramRoom_raisesConfigTooLargeError() -> (
    None
):
    config = runtime_config.RuntimeConfig(
        build_id="x" * 3550, checks=("identity",), checks_mask=32
    )

    with pytest.raises(errors.ConfigTooLargeError):
        runtime_library.write_config(_LIBRARY, config)


def testWriteConfig_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.write_config(b"not a library", _CONFIG)


def testWriteProgram_whenGivenALibrary_writesTheProgramIntoItsSection() -> None:
    program = bytes(range(256)) * 2

    library = runtime_library.write_program(_configured(), program)

    assert runtime_library.program(library) == program


def testWriteProgram_whenGivenALibrary_keepsTheConfigAndKeystoreSlot() -> None:
    program = bytes(range(256)) * 2

    library = runtime_library.write_program(_configured(), program)

    assert runtime_library.read_config(library) == _CONFIG.to_json()
    assert runtime_library.keystore(library) == bytes(key_schedule.KEY_SIZE)


def testWriteProgram_whenTheProgramIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="512 bytes"):
        runtime_library.write_program(_configured(), bytes(64))


def testWriteProgram_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.write_program(b"not a library", _PROGRAM)


def testProgram_whenThePackerWroteNoProgram_isAllZeros() -> None:
    assert runtime_library.program(_configured()) == bytes(key_schedule.PROGRAM_SIZE)


def testWriteKeystore_whenGivenALibrary_writesTheShareIntoTheSection() -> None:
    library = runtime_library.write_keystore(_configured(), _SHARE)

    assert runtime_library.keystore(library) == _SHARE


def testWriteKeystore_whenGivenALibrary_keepsTheRestOfTheSection() -> None:
    configured = _configured()
    program = bytes(range(256)) * 2
    with_program = runtime_library.write_program(configured, program)

    library = runtime_library.write_keystore(with_program, _SHARE)

    assert runtime_library.read_config(library) == _CONFIG.to_json()
    assert runtime_library.program(library) == program


def testWriteKeystore_whenTheShareIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        runtime_library.write_keystore(_configured(), bytes(31))


def testWriteKeystore_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.write_keystore(b"not a library", _SHARE)


def testConfigRegion_whenConfigProgramDigestAndKeystoreAreWritten_holdsThemAll() -> (
    None
):
    program = bytes(range(256)) * 2
    library = runtime_library.write_text_digest(
        runtime_library.write_program(_configured(), program),
        _DIGEST,
    )

    region = runtime_library.config_region(library)

    assert len(region) == 4096 - key_schedule.KEY_SIZE
    assert region.startswith(_CONFIG.to_json())
    assert region[
        len(_CONFIG.to_json()) : -key_schedule.PROGRAM_SIZE - key_schedule.KEY_SIZE
    ] == bytes(
        len(region)
        - len(_CONFIG.to_json())
        - key_schedule.PROGRAM_SIZE
        - key_schedule.KEY_SIZE
    )
    assert (
        region[
            -key_schedule.PROGRAM_SIZE - key_schedule.KEY_SIZE : -key_schedule.KEY_SIZE
        ]
        == program
    )
    assert region[-key_schedule.KEY_SIZE :] == _DIGEST


def testWriteTextDigest_whenGivenALibrary_writesTheDigestIntoTheSection() -> None:
    library = runtime_library.write_text_digest(
        runtime_library.write_keystore(_configured(), _SHARE), _DIGEST
    )

    assert runtime_library.text_digest(library) == _DIGEST


def testWriteTextDigest_whenGivenALibrary_keepsTheConfigProgramAndKeystore() -> None:
    program = bytes(range(256)) * 2
    library = runtime_library.write_text_digest(
        runtime_library.write_keystore(
            runtime_library.write_program(_configured(), program), _SHARE
        ),
        _DIGEST,
    )

    assert runtime_library.read_config(library) == _CONFIG.to_json()
    assert runtime_library.program(library) == program
    assert runtime_library.keystore(library) == _SHARE


def testWriteTextDigest_whenTheDigestIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        runtime_library.write_text_digest(_configured(), bytes(31))


def testTextDigest_whenThePackerWroteNoDigest_isAllZeros() -> None:
    assert runtime_library.text_digest(_configured()) == bytes(key_schedule.KEY_SIZE)


def testKeystore_whenThePackerWroteNoShare_isAllZeros() -> None:
    assert runtime_library.keystore(_configured()) == bytes(key_schedule.KEY_SIZE)


def testTextRegion_whenGivenALibrary_returnsItsExecutableCode() -> None:
    text = runtime_library.text_region(_LIBRARY)

    assert len(text) > 0
    assert text == runtime_library.text_region(_configured())


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
    with pytest.raises(errors.InvalidRuntimeError, match=r".data"):
        runtime_library.section_region(_LIBRARY, ".data")


def testFoldSections_whenGivenALibrary_returnsTheTableSectionsItHas() -> None:
    sections = runtime_library.fold_sections(_LIBRARY)

    assert ".rela.dyn" in sections
    assert ".text" not in sections
    assert set(sections) <= set(key_schedule.SECTION_NAMES)


def testTextRegion_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.text_region(b"not a library")
