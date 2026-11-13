"""Tests of the `rasp` command line."""

import contextlib
import errno
import json
import os
import pathlib
import zipfile
from importlib import metadata

import pytest

from rasp_packer import capabilities
from rasp_packer import cli
from rasp_packer import identity
from rasp_packer import packer
from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import packer as android_packer
from rasp_packer.android import resources as android_resources
from rasp_packer.android import runtime_library
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
        "\ncapabilities unknown (legacy runtime artifacts); effective checks "
        "\nlocal policy report_only; hash ; effective config ; host calls only, adaptation unverified"
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


@pytest.mark.parametrize("data", [b"{}", b" " * 2049])
def testMain_whenExplicitPolicyIsInvalid_failsBeforeCreatingOutput(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str], data: bytes
) -> None:
    filename = tmp_path / "policy.json"
    filename.write_bytes(data)
    result = cli.main([*_pack_arguments(tmp_path), "--local-policy", str(filename)])
    assert result == cli.EXIT_FAILED
    assert "policy" in capsys.readouterr().err
    assert (tmp_path / "out.ipa").exists() is False


@pytest.mark.parametrize("kind", ["apk", "aab"])
@pytest.mark.parametrize("damage", ["none", "mapping", "policy"])
def testMain_whenMappingAndLocalPolicyGiven_preservesBothProductionPaths(
    tmp_path: pathlib.Path, kind: str, damage: str
) -> None:
    artifacts = android_resources.load()
    if len(artifacts.policy_manifests) == 0:
        pytest.skip("requires installed native policy-support resources")
    source = pathlib.Path(__file__).parents[1] / "apps/android/InsecureBankv2.aab"
    app = source
    package = "com.android.insecurebankv2"
    if kind == "apk":
        package = "com.example.withapp"
        app = tmp_path / "input.apk"
        manifest = (
            pathlib.Path(__file__).parent
            / "android/apk/fixtures/manifest_with_application_and_version.bin"
        )
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(app, "w") as target:
            target.writestr("AndroidManifest.xml", manifest.read_bytes())
            for name in original.namelist():
                if name.startswith("base/dex/classes") and name.endswith(".dex"):
                    target.writestr(name.removeprefix("base/dex/"), original.read(name))
    mapping_file = tmp_path / "mapping.txt"
    mapped_class = (
        "absent.Class"
        if damage == "mapping"
        else "com.android.insecurebankv2.CryptoClass"
    )
    mapping_file.write_text(
        f"{package}.Original -> {mapped_class}:\n", encoding="utf-8"
    )
    policy_file = tmp_path / "policy.json"
    document = {
        "schema_version": 1,
        "engine_version": 1,
        "policy_id": "combined-options",
        "policy_version": 1,
        "mode": "report_only",
        "scope": "host_calls_only",
        "platform": "android",
        "catalogue_id": capabilities.catalogue_id(),
        "report_schema_version": 1,
        "report_reason_version": 1,
        "native_metadata_version": 1,
        "operations": [],
    }
    policy_file.write_text(
        "{}" if damage == "policy" else json.dumps(document), encoding="utf-8"
    )
    output = tmp_path / f"protected.{kind}"
    result = cli.main(
        [
            "pack",
            str(app),
            "--platform",
            "android",
            "--build-id",
            _BUILD_ID,
            "--output",
            str(output),
            "--mapping",
            str(mapping_file),
            "--local-policy",
            str(policy_file),
        ]
    )
    assert list(tmp_path.glob(".rasp-*")) == []
    if damage != "none":
        assert result == cli.EXIT_FAILED
        assert output.exists() is False
        return
    assert result == cli.EXIT_OK
    prefix = "base/" if kind == "aab" else ""
    with zipfile.ZipFile(output) as packed:
        key = packed.read(prefix + "assets/rasp/key.bin")
        class_map = cipher.decrypt(key, packed.read(prefix + "assets/rasp/map.bin"))
        assert b"com.android.insecurebankv2.CryptoClass," in class_map
        for abi in artifacts.libraries:
            library = packed.read(f"{prefix}lib/{abi}/librasp.so")
            config = json.loads(runtime_library.read_config(library))
            assert config["local_policy"] == document
            assert config["build_id"] == _BUILD_ID
