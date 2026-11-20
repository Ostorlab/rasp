"""Tests of the `rasp` command line."""

import io
import pathlib
import sys
from importlib import metadata

import pytest

from rasp_packer import build_ids
from rasp_packer import cli
from rasp_packer import identity
from rasp_packer import inspection
from rasp_packer import packer
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import packer as android_packer

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


def testMain_whenNoCommand_printsTheHelpAndReturnsOk(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Without a command the plain help is printed to stdout and the exit code is 0."""

    exit_code = cli.main([])

    out = capsys.readouterr().out
    assert exit_code == cli.EXIT_OK
    assert out.startswith("usage: rasp")
    assert "\x1b" not in out
    assert "pack" in out


def testMain_whenPlatformUnknown_exitsWithUsageError(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(_pack_arguments(tmp_path, platform="windows"))

    assert exit_info.value.code == _USAGE_ERROR


def testMain_whenBuildIdIsMissing_packsWithTheDerivedBuildId(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without --build-id, the packer gets the derived id and the success line shows it."""
    (tmp_path / "app.ipa").write_bytes(b"app bytes")
    calls: list[dict[str, object]] = []

    def fake_pack(**arguments: object) -> packer.PackResult:
        """Records the arguments of the pack and returns a result carrying the given build id."""
        calls.append(arguments)
        return packer.PackResult(
            output=tmp_path / "out.ipa",
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=str(arguments["build_id"]),
            skipped_checks=(),
        )

    monkeypatch.setattr(packer, "pack", fake_pack)
    arguments = _pack_arguments(tmp_path)
    del arguments[arguments.index("--build-id") : arguments.index("--build-id") + 2]
    expected = build_ids.default_build_id(
        app=tmp_path / "app.ipa", platform=platforms.Platform.IOS, checks=[]
    )

    exit_code = cli.main(arguments)

    assert exit_code == cli.EXIT_OK
    assert [call["build_id"] for call in calls] == [expected]
    assert f"build {expected})" in capsys.readouterr().out


def testMain_whenBuildIdIsMissingAndTheAppIsMissing_printsTheErrorAndReturnsFailed(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without --build-id and with an unreadable app, the command prints the error and fails."""
    arguments = _pack_arguments(tmp_path)
    del arguments[arguments.index("--build-id") : arguments.index("--build-id") + 2]

    exit_code = cli.main(arguments)

    assert exit_code == cli.EXIT_FAILED
    assert "cannot read" in capsys.readouterr().err


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
        return identity.AppIdentity(package_name="dev.ostorlab.demo", version="1.2.3")

    monkeypatch.setattr(android_packer, "pack", fake_pack)

    exit_code = cli.main(
        [*_pack_arguments(tmp_path, platform="android"), "--checks", "hooks,oldcheck"]
    )

    assert exit_code == cli.EXIT_OK
    assert [config.checks for config in configs] == [("hooks", "identity")]
    assert capsys.readouterr().err == (
        "rasp pack: warning: 'oldcheck' is not a check of android, skipped\n"
    )


def testMain_whenACheckIsATypo_warnsWithTheSuggestion(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checks that the warning for a skipped typo names the closest check."""

    monkeypatch.setattr(
        android_packer,
        "pack",
        lambda **_: identity.AppIdentity(
            package_name="dev.ostorlab.demo", version="1.2.3"
        ),
    )

    exit_code = cli.main(
        [*_pack_arguments(tmp_path, platform="android"), "--checks", "debuger"]
    )

    assert exit_code == cli.EXIT_OK
    assert capsys.readouterr().err == (
        "rasp pack: warning: 'debuger' is not a check of android, skipped. "
        "Did you mean 'debugger'?\n"
    )


def testMain_whenStrictAndACheckIsUnknown_printsTheErrorsAndPacksNothing(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checks that `--strict` prints an error per unknown id, fails and does not call the packer."""

    calls: list[object] = []

    def fake_pack(**kwargs: object) -> identity.AppIdentity:
        """Records the call and returns an identity."""
        calls.append(kwargs)
        return identity.AppIdentity(package_name="dev.ostorlab.demo", version="1.2.3")

    monkeypatch.setattr(android_packer, "pack", fake_pack)

    exit_code = cli.main(
        [
            *_pack_arguments(tmp_path, platform="android"),
            "--checks",
            "hooks,debuger,telepathy",
            "--strict",
        ]
    )

    assert exit_code == cli.EXIT_FAILED
    assert calls == []
    assert capsys.readouterr().err == (
        "rasp pack: error: 'debuger' is not a check of android. Did you mean 'debugger'?\n"
        "rasp pack: error: 'telepathy' is not a check of android.\n"
    )


def testMain_whenStrictAndChecksAreKnown_packsTheApp(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checks that `--strict` packs the app when every id is a check of the platform."""

    configs: list[runtime_config.RuntimeConfig] = []

    def fake_pack(
        *, config: runtime_config.RuntimeConfig, **_: object
    ) -> identity.AppIdentity:
        """Records the config and returns an identity."""
        configs.append(config)
        return identity.AppIdentity(package_name="dev.ostorlab.demo", version="1.2.3")

    monkeypatch.setattr(android_packer, "pack", fake_pack)

    exit_code = cli.main(
        [
            *_pack_arguments(tmp_path, platform="android"),
            "--checks",
            "hooks",
            "--strict",
        ]
    )

    assert exit_code == cli.EXIT_OK
    assert [config.checks for config in configs] == [("hooks", "identity")]


def testMain_whenStrictWithoutChecks_warnsAndPacksWithTheRequiredChecks(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checks that `--strict` without `--checks` warns, packs with the required checks and exits 0."""

    configs: list[runtime_config.RuntimeConfig] = []

    def fake_pack(
        *, config: runtime_config.RuntimeConfig, **_: object
    ) -> identity.AppIdentity:
        """Records the config and returns an identity."""
        configs.append(config)
        return identity.AppIdentity(package_name="dev.ostorlab.demo", version="1.2.3")

    monkeypatch.setattr(android_packer, "pack", fake_pack)

    exit_code = cli.main([*_pack_arguments(tmp_path, platform="android"), "--strict"])

    assert exit_code == cli.EXIT_OK
    assert [config.checks for config in configs] == [("identity",)]
    assert "no --checks given" in capsys.readouterr().err


def testMain_whenPackSucceeds_printsTheAppIdentityAndTheBuildId(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first line printed names the app identity and the build id."""
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
    assert capsys.readouterr().out.splitlines()[0] == (
        f"packed ios app: {tmp_path / 'out.ipa'} "
        f"(package dev.ostorlab.demo, version 1.2.3, build {_BUILD_ID})"
    )


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


def testMain_whenInspectedAppIsProtected_printsAlignedLabelsAndValues(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A protected app prints every field as an aligned label and value."""
    monkeypatch.setattr(
        inspection,
        "inspect",
        lambda **_: inspection.InspectResult(
            protected=True,
            package_name="dev.ostorlab.demo",
            version="1.2.3",
            build_id=_BUILD_ID,
            checks=("debugger", "identity"),
            abis=("arm64-v8a", "x86_64"),
        ),
    )

    exit_code = cli.main(
        ["inspect", str(tmp_path / "app.apk"), "--platform", "android"]
    )

    assert exit_code == cli.EXIT_OK
    assert capsys.readouterr().out == (
        "protected  yes\n"
        "package    dev.ostorlab.demo\n"
        "version    1.2.3\n"
        f"build id   {_BUILD_ID}\n"
        "checks     debugger,identity\n"
        "abis       arm64-v8a,x86_64\n"
    )


def testMain_whenInspectedAppIsNotProtected_printsOnlyTheIdentity(
    ipa_file: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unprotected app prints that it is not protected, with its package and version only."""
    exit_code = cli.main(["inspect", str(ipa_file), "--platform", "ios"])

    assert exit_code == cli.EXIT_OK
    assert capsys.readouterr().out == (
        "protected  no\npackage    dev.ostorlab.demo\nversion    1.2.3\n"
    )


def testMain_whenInspectFails_printsTheErrorAndReturnsFailed(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file that is not an app prints the error to stderr and nothing to stdout."""
    app = tmp_path / "app.ipa"
    app.write_bytes(b"not a zip")

    exit_code = cli.main(["inspect", str(app), "--platform", "ios"])

    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_FAILED
    assert captured.out == ""
    assert captured.err.startswith("rasp inspect: ")


def testMain_whenPackSucceeds_printsTheUnsignedReminderAfterTheResultLine(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The line after the result line reminds that the protected app is unsigned."""
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

    lines = capsys.readouterr().out.splitlines()
    assert exit_code == cli.EXIT_OK
    assert lines[0].startswith("packed ios app: ")
    assert lines[1:] == [
        "next: the protected app is unsigned; sign it with your upload or release key before you upload it"
    ]


class _Terminal(io.StringIO):
    """A stdout that is a terminal."""

    def isatty(self) -> bool:
        """Returns True."""
        return True


def _use_terminal(monkeypatch: pytest.MonkeyPatch) -> _Terminal:
    """Replaces stdout with a terminal and clears the variables that turn the banner off."""
    terminal = _Terminal()
    monkeypatch.setattr(sys, "stdout", terminal)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    return terminal


def testMain_whenNoCommandOnATerminal_printsTheBannerThenTheHelp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On a terminal, the banner with the version comes before the help."""

    terminal = _use_terminal(monkeypatch)

    exit_code = cli.main([])

    out = terminal.getvalue()
    assert exit_code == cli.EXIT_OK
    assert out.index("██████╗") < out.index("Protects built Android")
    assert f"apps · {metadata.version('rasp-packer')}" in out


@pytest.mark.parametrize("flag", ["--help", "-h"])
def testMain_whenHelpRequestedOnATerminal_printsTheBannerAboveTheHelp(
    monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    """On a terminal, --help and -h print the banner above the help."""

    terminal = _use_terminal(monkeypatch)

    with pytest.raises(SystemExit) as exit_info:
        cli.main([flag])

    out = terminal.getvalue()
    assert exit_info.value.code == cli.EXIT_OK
    assert out.index("██████╗") < out.index("Protects built Android")


def testMain_whenHelpRequestedAndStdoutIsNotATerminal_printsThePlainHelp(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Off a terminal, the help has no banner and no escape sequences."""

    with pytest.raises(SystemExit):
        cli.main(["--help"])

    out = capsys.readouterr().out
    assert out.startswith("usage: rasp")
    assert "\x1b" not in out
    assert "█" not in out


def testMain_whenSubcommandHelpRequestedOnATerminal_printsNoBanner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The help of a subcommand has no banner."""

    terminal = _use_terminal(monkeypatch)

    with pytest.raises(SystemExit):
        cli.main(["pack", "--help"])

    assert "█" not in terminal.getvalue()
