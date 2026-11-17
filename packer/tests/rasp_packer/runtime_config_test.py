"""Tests of the runtime's config, and of writing it into and reading it from a space of a binary."""

import json

import pytest

from rasp_packer import errors
from rasp_packer import runtime_config

_CONFIG = runtime_config.RuntimeConfig(
    build_id="build-1", checks=("identity",), checks_mask=32
)
_SPACE = runtime_config.ConfigSpace(offset=4, size=64)
_BINARY = b"head" + b"{}" + bytes(62) + b"tail"


def testToJson_whenGivenABuildIdAndMask_writesAJsonObjectWithThem() -> None:
    config = runtime_config.RuntimeConfig(
        build_id="build-1", checks=("identity",), checks_mask=32
    )

    assert config.to_json() == b'{"build_id":"build-1","m":32}'


def testToJson_whenGivenAMask_writesItAsANumber() -> None:
    config = runtime_config.RuntimeConfig(
        build_id="build-1", checks=("debugger", "identity"), checks_mask=3
    )

    assert config.to_json() == b'{"build_id":"build-1","m":3}'


def testToJson_whenTheBuildIdIsNotAscii_writesItInUtf8() -> None:
    config = runtime_config.RuntimeConfig(
        build_id='bühl "7"', checks=("identity",), checks_mask=32
    )

    assert json.loads(config.to_json()) == {"build_id": 'bühl "7"', "m": 32}
    assert "ü".encode() in config.to_json()


def testReadConfig_whenNothingWasWritten_readsTheSpaceUpToItsFirstZeroByte() -> None:
    assert runtime_config.read_config(_BINARY, _SPACE) == b"{}"


def testWriteConfig_whenItFits_writesTheJsonThenZeroBytesOverTheSpaceOnly() -> None:
    binary = runtime_config.write_config(_BINARY, _SPACE, _CONFIG)

    assert (
        binary
        == b"head" + _CONFIG.to_json() + bytes(64 - len(_CONFIG.to_json())) + b"tail"
    )
    assert runtime_config.read_config(binary, _SPACE) == _CONFIG.to_json()


def testWriteConfig_whenWrittenTwice_keepsOnlyTheSecondConfig() -> None:
    longer = runtime_config.RuntimeConfig(
        build_id="a longer id", checks=("identity",), checks_mask=32
    )
    first = runtime_config.write_config(_BINARY, _SPACE, longer)

    binary = runtime_config.write_config(first, _SPACE, _CONFIG)

    assert runtime_config.read_config(binary, _SPACE) == _CONFIG.to_json()


def testWriteConfig_whenTheJsonFillsTheWholeSpace_raisesConfigTooLargeError() -> None:
    config = runtime_config.RuntimeConfig(
        build_id="x" * (64 - len('{"build_id":"","m":0}')),
        checks=("identity",),
        checks_mask=0,
    )

    with pytest.raises(errors.ConfigTooLargeError):
        runtime_config.write_config(_BINARY, _SPACE, config)
