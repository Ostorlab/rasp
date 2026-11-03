"""Tests of the `rasp` command line."""

import pathlib
from importlib import metadata

import pytest

from rasp_packer import cli
from rasp_packer import packer

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


def testMain_whenChecksAreGiven_passesThemToThePacker(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    def fake_pack(**arguments: object) -> packer.PackResult:
        calls.append(arguments)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
        )

    monkeypatch.setattr(packer, "pack", fake_pack)

    cli.main([*_pack_arguments(tmp_path), "--checks", "jailbreak,identity"])

    assert [call["checks"] for call in calls] == [["jailbreak", "identity"]]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("debugger, identity", ["debugger", "identity"]), ("debugger,", ["debugger"])],
)
def testMain_whenChecksHaveSpacesOrATrailingComma_passesTheIdsAloneToThePacker(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    expected: list[str],
) -> None:
    calls: list[dict[str, object]] = []

    def fake_pack(**arguments: object) -> packer.PackResult:
        calls.append(arguments)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
        )

    monkeypatch.setattr(packer, "pack", fake_pack)

    exit_code = cli.main([*_pack_arguments(tmp_path), "--checks", value])

    assert exit_code == cli.EXIT_OK
    assert [call["checks"] for call in calls] == [expected]


@pytest.mark.parametrize("value", ["", ",", " ", " , "])
def testMain_whenChecksHaveNoId_exitsWithUsageError(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main([*_pack_arguments(tmp_path), "--checks", value])

    assert exit_info.value.code == _USAGE_ERROR
    assert "give at least one check id" in capsys.readouterr().err


def testMain_whenChecksAreNotGiven_passesNoChecksToThePacker(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    def fake_pack(**arguments: object) -> packer.PackResult:
        calls.append(arguments)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
        )

    monkeypatch.setattr(packer, "pack", fake_pack)

    cli.main(_pack_arguments(tmp_path))

    assert [call["checks"] for call in calls] == [None]


def testMain_whenACheckIsUnknown_printsTheErrorAndReturnsFailed(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main([*_pack_arguments(tmp_path), "--checks", "telepathy"])

    assert exit_code == cli.EXIT_FAILED
    assert "the check 'telepathy' does not exist for ios" in capsys.readouterr().err


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
