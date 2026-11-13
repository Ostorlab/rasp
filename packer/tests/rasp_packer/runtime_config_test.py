"""Tests of the runtime's config, and of writing it into and reading it from a space of a binary."""

import json

import pytest

from rasp_packer import errors
from rasp_packer import runtime_config

_CONFIG = runtime_config.RuntimeConfig(build_id="build-1", checks=("identity",))
_SPACE = runtime_config.ConfigSpace(offset=4, size=64)
_BINARY = b"head" + b"{}" + bytes(62) + b"tail"


def testToJson_whenGivenABuildIdAndChecks_writesAJsonObjectWithThem() -> None:
    config = runtime_config.RuntimeConfig(build_id="build-1", checks=("identity",))

    assert config.to_json() == b'{"build_id":"build-1","checks":["identity"]}'


def testToJson_whenGivenChecks_writesThemAsAnArray() -> None:
    config = runtime_config.RuntimeConfig(
        build_id="build-1", checks=("debugger", "identity")
    )

    assert (
        config.to_json() == b'{"build_id":"build-1","checks":["debugger","identity"]}'
    )


def testToJson_whenTheBuildIdIsNotAscii_writesItInUtf8() -> None:
    config = runtime_config.RuntimeConfig(build_id='bühl "7"', checks=("identity",))

    assert json.loads(config.to_json()) == {
        "build_id": 'bühl "7"',
        "checks": ["identity"],
    }
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
    longer = runtime_config.RuntimeConfig(build_id="a longer id", checks=("identity",))
    first = runtime_config.write_config(_BINARY, _SPACE, longer)

    binary = runtime_config.write_config(first, _SPACE, _CONFIG)

    assert runtime_config.read_config(binary, _SPACE) == _CONFIG.to_json()


def testWriteConfig_whenTheJsonFillsTheWholeSpace_raisesConfigTooLargeError() -> None:
    config = runtime_config.RuntimeConfig(
        build_id="x" * (64 - len('{"build_id":"","checks":["identity"]}')),
        checks=("identity",),
    )

    with pytest.raises(errors.ConfigTooLargeError):
        runtime_config.write_config(_BINARY, _SPACE, config)


@pytest.mark.parametrize(
    "space",
    [
        runtime_config.ConfigSpace(offset=-1, size=4),
        runtime_config.ConfigSpace(offset=4, size=1000),
        runtime_config.ConfigSpace(offset=4, size=0),
        runtime_config.ConfigSpace(offset=0, size=65537),
    ],
)
def testReadConfig_whenSectionBoundsInvalid_rejects(
    space: runtime_config.ConfigSpace,
) -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="config"):
        runtime_config.read_config(_BINARY, space)


def testReadConfig_whenUnterminated_rejects() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="terminated"):
        runtime_config.read_config(
            b"x" * 64, runtime_config.ConfigSpace(offset=0, size=64)
        )


@pytest.mark.parametrize(
    "space",
    [
        runtime_config.ConfigSpace(offset=-1, size=64),
        runtime_config.ConfigSpace(offset=4, size=1000),
        runtime_config.ConfigSpace(offset=0, size=65537),
    ],
)
def testWriteConfig_whenSectionBoundsInvalid_rejects(
    space: runtime_config.ConfigSpace,
) -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="config"):
        runtime_config.write_config(_BINARY, space, _CONFIG)


def testRuntimeConfig_whenPolicyIsAbsent_exposesReportOnlyDefault() -> None:
    assert _CONFIG.local_policy is None


def testReadConfig_whenPaddingIsNonzero_rejectsTheNativeInvalidEnvelope() -> None:
    with pytest.raises(errors.InvalidRuntimeError, match="padding"):
        runtime_config.read_config(
            b"{}\0\0x", runtime_config.ConfigSpace(offset=0, size=5)
        )
