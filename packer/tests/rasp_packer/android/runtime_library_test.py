"""Tests of writing the runtime's config into, and reading it from, the Android runtime library."""

import pytest

from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.android import runtime_library
from tests.rasp_packer import conftest

_CONFIG = runtime_config.RuntimeConfig(build_id="build-1")
_LIBRARY = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()


def testReadConfig_whenThePackerWroteNoConfig_readsTheRuntimesEmptyConfig() -> None:
    assert runtime_library.read_config(_LIBRARY) == b"{}"


def testWriteConfig_whenGivenALibrary_writesTheConfigIntoItsSection() -> None:
    library = runtime_library.write_config(_LIBRARY, _CONFIG)

    assert runtime_library.read_config(library) == _CONFIG.to_json()


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


def testWriteConfig_whenTheConfigDoesNotFit_raisesConfigTooLargeError() -> None:
    config = runtime_config.RuntimeConfig(build_id="x" * 4096)

    with pytest.raises(errors.ConfigTooLargeError):
        runtime_library.write_config(_LIBRARY, config)


def testWriteConfig_whenNotAnElfFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not an ELF file"):
        runtime_library.write_config(b"not a library", _CONFIG)
