"""Tests of the `rasp` command line."""

import pathlib
from importlib import metadata

import pytest

from rasp_packer import cli
from rasp_packer import packer
from rasp_packer import plugin_configs

_BUILD_ID = "a" * 64
_USAGE_ERROR = 2


def _pack_arguments(
    tmp_path: pathlib.Path,
    *,
    platform: str = "ios",
    build_id: str = _BUILD_ID,
) -> list[str]:
    """Returns the `rasp pack` arguments for an app and output in `tmp_path`."""
    return [
        "pack",
        str(tmp_path / "app.ipa"),
        "--platform",
        platform,
        "--build-id",
        build_id,
        "--output",
        str(tmp_path / "out.ipa"),
    ]


def testMain_whenVersionRequested_printsTheInstalledVersion(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])

    assert exit_info.value.code == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == f"rasp {metadata.version('rasp-packer')}"


def testMain_whenNoCommand_exitsWithUsageError() -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main([])

    assert exit_info.value.code == _USAGE_ERROR


def testMain_whenPlatformUnknown_exitsWithUsageError(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(_pack_arguments(tmp_path, platform="windows"))

    assert exit_info.value.code == _USAGE_ERROR


def testMain_whenBuildIdIsMissing_exitsWithUsageError(tmp_path: pathlib.Path) -> None:
    arguments = _pack_arguments(tmp_path)
    del arguments[arguments.index("--build-id") : arguments.index("--build-id") + 2]

    with pytest.raises(SystemExit) as exit_info:
        cli.main(arguments)

    assert exit_info.value.code == _USAGE_ERROR


def testMain_whenBuildIdIsEmpty_printsTheErrorAndReturnsFailed(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main(_pack_arguments(tmp_path, build_id=""))

    assert exit_code == cli.EXIT_FAILED
    assert "the build id is empty" in capsys.readouterr().err


def testMain_whenPackFails_printsTheErrorAndReturnsFailed(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main(_pack_arguments(tmp_path))

    assert exit_code == cli.EXIT_FAILED
    assert capsys.readouterr().err.startswith("rasp pack: ")


def testMain_whenPackSucceeds_printsTheAppIdentityAndTheBuildId(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        packer,
        "pack",
        lambda **_: packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
        ),
    )

    exit_code = cli.main(_pack_arguments(tmp_path))

    assert exit_code == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == (
        f"packed ios app: {tmp_path / 'out.ipa'} "
        f"(package dev.ostorlab.demo, version 1.2.3, build {_BUILD_ID})"
    )


def _record_pack(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> list[object]:
    """Replaces packer.pack with a fake that succeeds, and returns the plugin configs of each call."""
    received: list[object] = []

    def fake_pack(*, plugin_configs: object, **_: object) -> packer.PackResult:
        received.append(plugin_configs)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
        )

    monkeypatch.setattr(packer, "pack", fake_pack)
    return received


def testMain_whenPluginConfigsAreGiven_packsThemInTheOrderGiven(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    received = _record_pack(tmp_path, monkeypatch)
    (tmp_path / "zeta.conf").write_bytes(b"z=1")
    (tmp_path / "alpha.conf").write_bytes(b"a=2")

    exit_code = cli.main(
        [
            *_pack_arguments(tmp_path),
            "--plugin-config",
            f"zeta={tmp_path / 'zeta.conf'}",
            "--plugin-config",
            f"alpha={tmp_path / 'alpha.conf'}",
        ]
    )

    assert exit_code == cli.EXIT_OK
    assert received == [
        (
            plugin_configs.PluginConfig(name="zeta", data=b"z=1"),
            plugin_configs.PluginConfig(name="alpha", data=b"a=2"),
        )
    ]


def testMain_whenNoPluginConfigIsGiven_packsNone(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    received = _record_pack(tmp_path, monkeypatch)

    assert cli.main(_pack_arguments(tmp_path)) == cli.EXIT_OK
    assert received == [()]


def testMain_whenAPluginConfigCannotBeRead_printsTheErrorAndReturnsFailed(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received = _record_pack(tmp_path, monkeypatch)

    exit_code = cli.main(
        [
            *_pack_arguments(tmp_path),
            "--plugin-config",
            f"example={tmp_path / 'missing.conf'}",
        ]
    )

    assert exit_code == cli.EXIT_FAILED
    assert capsys.readouterr().err.startswith("rasp pack: cannot read the config")
    assert received == []
