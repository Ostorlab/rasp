"""Tests of the `rasp` command line."""

import contextlib
import errno
import os
import pathlib
from importlib import metadata

import pytest

from rasp_packer import cli
from rasp_packer import identity
from rasp_packer import packer
from rasp_packer import runtime_config
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import resources as ios_resources

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
    exit_code = cli.main([*_pack_arguments(tmp_path), "--checks", "debugger"])

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
            skipped_checks=(),
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
            skipped_checks=(),
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


def testMain_whenChecksAreNotGiven_warnsAndPassesNoChecksToThePacker(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def fake_pack(**arguments: object) -> packer.PackResult:
        calls.append(arguments)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
            skipped_checks=(),
        )

    monkeypatch.setattr(packer, "pack", fake_pack)

    exit_code = cli.main(_pack_arguments(tmp_path))

    assert exit_code == cli.EXIT_OK
    assert [call["checks"] for call in calls] == [[]]
    assert capsys.readouterr().err == (
        "rasp pack: warning: no --checks given, so the app runs only the required checks: "
        "identity. Pass --checks, such as --checks debugger,hooks, to choose the checks it "
        "runs.\n"
    )


def testMain_whenACheckIsUnknown_warnsAndPacksWithTheOtherChecks(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configs: list[runtime_config.RuntimeConfig] = []

    def fake_pack(
        *, config: runtime_config.RuntimeConfig, **_: object
    ) -> identity.AppIdentity:
        configs.append(config)
        return identity.AppIdentity(
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            effective_checks=config.checks,
        )

    monkeypatch.setattr(android_packer, "pack", fake_pack)

    exit_code = cli.main(
        [*_pack_arguments(tmp_path, platform="android"), "--checks", "hooks,oldcheck"]
    )

    assert exit_code == cli.EXIT_OK
    assert [config.checks for config in configs] == [("hooks", "identity")]
    assert capsys.readouterr().err == (
        "rasp pack: warning: 'oldcheck' is not a check of android, skipped\n"
    )


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
            skipped_checks=(),
        ),
    )

    exit_code = cli.main(_pack_arguments(tmp_path))

    assert exit_code == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == (
        f"packed ios app: {tmp_path / 'out.ipa'} "
        f"(package dev.ostorlab.demo, version 1.2.3, build {_BUILD_ID}; unsigned, structurally verified)"
        "\ncapabilities unknown (legacy runtime artifacts); effective checks"
    )


def testPack_whenLegacyRuntime_reportsUnknownCapabilities(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        packer,
        "pack",
        lambda **_: packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="demo",
            version="1",
            build_id="build",
            skipped_checks=(),
            effective_checks=("identity",),
        ),
    )
    assert cli.main([*_pack_arguments(tmp_path), "--checks", "identity"]) == cli.EXIT_OK
    assert "capabilities unknown" in capsys.readouterr().out


def testMain_whenPackedRuntimeHasWrongArchitecture_failsWithoutSuccessfulOutput(
    ipa_file: pathlib.Path,
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    library = runtime / "RaspRuntime"
    data = bytearray(library.read_bytes())
    data[4:8] = (0x01000007).to_bytes(4, "little")
    library.write_bytes(data)
    monkeypatch.setattr(
        ios_resources, "framework", lambda _: contextlib.nullcontext(runtime)
    )
    arguments = _pack_arguments(tmp_path)
    arguments[1] = str(ipa_file)

    assert cli.main(arguments) == cli.EXIT_FAILED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unsupported Mach-O architecture" in captured.err
    assert (tmp_path / "out.ipa").exists() is False
    assert list(tmp_path.glob(".rasp-*")) == []


@pytest.mark.parametrize("failure", ["missing_parent", "hard_link"])
def testMain_whenOutputCannotBePublished_reportsCleanErrorWithoutOutput(
    ipa_file: pathlib.Path,
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    monkeypatch.setattr(
        ios_resources, "framework", lambda _: contextlib.nullcontext(runtime)
    )
    arguments = _pack_arguments(tmp_path)
    arguments[1] = str(ipa_file)
    output = tmp_path / "out.ipa"
    if failure == "missing_parent":
        output = tmp_path / "missing" / "out.ipa"
        arguments[-1] = str(output)
    else:

        def fail_link(*args: object, **kwargs: object) -> None:
            raise OSError(errno.EOPNOTSUPP, "hard links unavailable")

        monkeypatch.setattr(os, "link", fail_link)
    assert cli.main([*arguments, "--checks", "identity"]) == cli.EXIT_FAILED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("rasp pack: cannot ")
    assert "Traceback" not in captured.err
    assert output.exists() is False
    assert list(tmp_path.glob(".rasp-*")) == []


def testMain_whenMappingGiven_passesTheMappingPathToPack(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_pack(**kwargs: object) -> packer.PackResult:
        captured.update(kwargs)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
            skipped_checks=(),
        )

    monkeypatch.setattr(packer, "pack", fake_pack)
    mapping_file = tmp_path / "mapping.txt"

    cli.main([*_pack_arguments(tmp_path), "--mapping", str(mapping_file)])

    assert captured["mapping"] == mapping_file


def testMain_whenNoMapping_passesNoneAsTheMapping(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_pack(**kwargs: object) -> packer.PackResult:
        captured.update(kwargs)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
            skipped_checks=(),
        )

    monkeypatch.setattr(packer, "pack", fake_pack)

    cli.main(_pack_arguments(tmp_path))

    assert captured["mapping"] is None

