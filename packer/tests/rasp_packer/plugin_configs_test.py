"""Tests of reading plugin configs."""

import pathlib

import pytest

from rasp_packer import errors
from rasp_packer import plugin_configs


def _write(tmp_path: pathlib.Path, name: str, data: bytes) -> pathlib.Path:
    """Writes `data` to the file `name` in `tmp_path` and returns its path."""
    path = tmp_path / name
    path.write_bytes(data)
    return path


def testRead_whenArgumentsAreValid_returnsTheConfigsInOrder(
    tmp_path: pathlib.Path,
) -> None:
    zeta = _write(tmp_path, "zeta.conf", b"z=1")
    alpha = _write(tmp_path, "alpha.conf", b"a=2")

    configs = plugin_configs.read([f"zeta={zeta}", f"alpha={alpha}"])

    assert configs == (
        plugin_configs.PluginConfig(name="zeta", data=b"z=1"),
        plugin_configs.PluginConfig(name="alpha", data=b"a=2"),
    )


def testRead_whenNoArgumentIsGiven_returnsNoConfig() -> None:
    assert plugin_configs.read([]) == ()


def testRead_whenTheFileIsEmpty_returnsAnEmptyConfig(tmp_path: pathlib.Path) -> None:
    empty = _write(tmp_path, "empty.conf", b"")

    assert plugin_configs.read([f"example={empty}"]) == (
        plugin_configs.PluginConfig(name="example", data=b""),
    )


def testRead_whenTheFileIsExactlyTheMaximum_returnsIt(tmp_path: pathlib.Path) -> None:
    data = b"x" * plugin_configs.MAX_SIZE
    path = _write(tmp_path, "large.conf", data)

    assert plugin_configs.read([f"example={path}"])[0].data == data


def testRead_whenTheFileIsLargerThanTheMaximum_raisesInvalidPluginConfigError(
    tmp_path: pathlib.Path,
) -> None:
    path = _write(tmp_path, "large.conf", b"x" * (plugin_configs.MAX_SIZE + 1))

    with pytest.raises(errors.InvalidPluginConfigError, match="larger than 65536"):
        plugin_configs.read([f"example={path}"])


@pytest.mark.parametrize("argument", ["example", "example=", "=config"])
def testRead_whenAnArgumentIsNotNameEqualsFile_raisesInvalidPluginConfigError(
    argument: str,
) -> None:
    with pytest.raises(errors.InvalidPluginConfigError):
        plugin_configs.read([argument])


def testRead_whenANameIsGivenTwice_raisesInvalidPluginConfigError(
    tmp_path: pathlib.Path,
) -> None:
    path = _write(tmp_path, "example.conf", b"")

    with pytest.raises(
        errors.InvalidPluginConfigError, match="more than once: example"
    ):
        plugin_configs.read([f"example={path}", f"example={path}"])


def testRead_whenTheFileIsMissing_raisesInvalidPluginConfigError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.InvalidPluginConfigError, match="cannot read"):
        plugin_configs.read([f"example={tmp_path / 'missing.conf'}"])


@pytest.mark.parametrize("name", ["Example", "1example", "plugin/config", "a" * 33])
def testPluginConfig_whenTheNameIsInvalid_raisesInvalidPluginConfigError(
    name: str,
) -> None:
    with pytest.raises(errors.InvalidPluginConfigError, match="doesn't match"):
        plugin_configs.PluginConfig(name=name, data=b"")


def testPluginConfig_whenTheNameIsTheLongestAccepted_keepsIt() -> None:
    name = "a" + "_" * 31

    assert plugin_configs.PluginConfig(name=name, data=b"").name == name
