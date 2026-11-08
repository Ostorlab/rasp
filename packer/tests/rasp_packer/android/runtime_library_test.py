"""Tests of writing the runtime's config and keystore into, and reading them from, the Android runtime library."""

import io

import lief
import pytest

from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.android import key_schedule
from rasp_packer.android import runtime_library
from tests.rasp_packer import conftest

_CONFIG = runtime_config.RuntimeConfig(build_id="build-1", checks=("identity",))
_LIBRARY = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
_SHARE = bytes(range(32, 64))


def testReadConfig_whenThePackerWroteNoConfig_readsTheRuntimesEmptyConfig() -> None:
    assert runtime_library.read_config(_LIBRARY) == b"{}"


def testWriteConfig_whenGivenALibrary_writesTheConfigIntoItsSection() -> None:
    library = runtime_library.write_config(_LIBRARY, _CONFIG)

    assert runtime_library.read_config(library) == _CONFIG.to_json()


def testWriteConfig_whenGivenALibrary_zeroesTheKeystoreSlot() -> None:
    library = runtime_library.write_config(_LIBRARY, _CONFIG)

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


def testWriteConfig_whenTheConfigLeavesNoKeystoreRoom_raisesConfigTooLargeError() -> (
    None
):
    config = runtime_config.RuntimeConfig(build_id="x" * 4063, checks=("identity",))

    with pytest.raises(errors.ConfigTooLargeError):
        runtime_library.write_config(_LIBRARY, config)


def testWriteConfig_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.write_config(b"not a library", _CONFIG)


def testWriteKeystore_whenGivenALibrary_writesTheShareIntoTheSection() -> None:
    library = runtime_library.write_keystore(_LIBRARY, _SHARE)

    assert runtime_library.keystore(library) == _SHARE


def testWriteKeystore_whenGivenALibrary_keepsTheRestOfTheSection() -> None:
    configured = runtime_library.write_config(_LIBRARY, _CONFIG)

    library = runtime_library.write_keystore(configured, _SHARE)

    assert runtime_library.read_config(library) == _CONFIG.to_json()
    assert runtime_library.config_region(library) == runtime_library.config_region(
        configured
    )


def testWriteKeystore_whenTheShareIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        runtime_library.write_keystore(_LIBRARY, bytes(31))


def testWriteKeystore_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.write_keystore(b"not a library", _SHARE)


def testConfigRegion_whenConfigAndKeystoreAreWritten_holdsTheJsonAndItsPadding() -> (
    None
):
    library = runtime_library.write_keystore(
        runtime_library.write_config(_LIBRARY, _CONFIG), _SHARE
    )

    region = runtime_library.config_region(library)

    assert len(region) == 4096 - key_schedule.KEY_SIZE
    assert region.startswith(_CONFIG.to_json())
    assert region[len(_CONFIG.to_json()) :] == bytes(
        len(region) - len(_CONFIG.to_json())
    )


def testKeystore_whenThePackerWroteNoShare_isAllZeros() -> None:
    assert runtime_library.keystore(_LIBRARY) == bytes(key_schedule.KEY_SIZE)


def testTextRegion_whenGivenALibrary_returnsItsExecutableCode() -> None:
    text = runtime_library.text_region(_LIBRARY)

    assert len(text) > 0
    assert text == runtime_library.text_region(
        runtime_library.write_config(_LIBRARY, _CONFIG)
    )


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


def testTextRegion_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.text_region(b"not a library")
