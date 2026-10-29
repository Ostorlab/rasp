"""Tests of writing the runtime's config into, and reading it from, the iOS runtime binary."""

import pytest

from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.ios import runtime_binary
from tests.rasp_packer import conftest

_CONFIG = runtime_config.RuntimeConfig(build_id="build-1")
_BINARY = (conftest.RUNTIME_CONFIG_DATA / "RaspRuntime").read_bytes()
_UNIVERSAL_BINARY = (
    conftest.RUNTIME_CONFIG_DATA / "RaspRuntime-universal"
).read_bytes()


def testWriteConfig_whenGivenABinary_writesTheConfigIntoItsSection() -> None:
    binary = runtime_binary.write_config(_BINARY, _CONFIG)

    assert len(binary) == len(_BINARY)
    assert runtime_binary.read_config(binary) == [_CONFIG.to_json()]


def testWriteConfig_whenGivenAUniversalBinary_writesTheConfigIntoEverySlice() -> None:
    assert runtime_binary.read_config(_UNIVERSAL_BINARY) == [b"{}", b"{}"]

    binary = runtime_binary.write_config(_UNIVERSAL_BINARY, _CONFIG)

    assert len(binary) == len(_UNIVERSAL_BINARY)
    assert runtime_binary.read_config(binary) == [
        _CONFIG.to_json(),
        _CONFIG.to_json(),
    ]


def testWriteConfig_whenTheConfigDoesNotFit_raisesConfigTooLargeError() -> None:
    config = runtime_config.RuntimeConfig(build_id="x" * 4096)

    with pytest.raises(errors.ConfigTooLargeError):
        runtime_binary.write_config(_BINARY, config)


def testWriteConfig_whenNotAMachoFile_raisesInvalidRuntimeError() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="not a Mach-O file"):
        runtime_binary.write_config(b"not a binary", _CONFIG)
