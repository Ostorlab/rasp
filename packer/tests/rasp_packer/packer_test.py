"""Tests of the packer's entry point."""

import pathlib

import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import packer
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import packer as ios_packer

_BUILD_ID = "a" * 64
_IDENTITY = identity.AppIdentity(package_name="dev.ostorlab.demo", version="1.2.3")


def testPack_whenIosApp_packsWithAConfigHoldingTheGivenBuildId(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, config: object, **_: object
    ) -> identity.AppIdentity:
        calls["app"] = app
        calls["output"] = output
        calls["config"] = config
        return _IDENTITY

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
        checks=["identity"],
    )

    assert calls == {
        "app": ipa_file,
        "output": tmp_path / "out.ipa",
        "config": runtime_config.RuntimeConfig(
            build_id=_BUILD_ID, checks=("identity",)
        ),
    }


def testPack_whenIosApp_returnsTheProtectedAppItsIdentityAndTheBuildId(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ios_packer, "pack", lambda **_: _IDENTITY)

    result = packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
        checks=["identity"],
    )

    assert result == packer.PackResult(
        output=tmp_path / "out.ipa",
        package_name="dev.ostorlab.demo",
        version="1.2.3",
        build_id=_BUILD_ID,
        skipped_checks=(),
    )


def testPack_whenBuildIdHasAnyFormat_packsItAsGiven(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ios_packer, "pack", lambda **_: _IDENTITY)

    result = packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id="build-1",
        checks=["identity"],
    )

    assert result.build_id == "build-1"


@pytest.mark.parametrize(
    ("build_id", "message"),
    [("", "empty"), ("build\n1", "control characters")],
)
def testPack_whenBuildIdCannotBeWritten_raisesInvalidBuildIdError(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, build_id: str, message: str
) -> None:
    with pytest.raises(errors.InvalidBuildIdError, match=message):
        packer.pack(
            app=ipa_file,
            platform=platforms.Platform.IOS,
            output=tmp_path / "out.ipa",
            build_id=build_id,
            checks=["identity"],
        )


def testPack_whenGivenChecks_packsWithAConfigHoldingThemSortedWithTheRequiredOnes(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configs: list[object] = []

    def fake_pack(*, config: object, **_: object) -> identity.AppIdentity:
        configs.append(config)
        return _IDENTITY

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
        checks=["jailbreak", "debugger"],
    )

    assert configs == [
        runtime_config.RuntimeConfig(
            build_id=_BUILD_ID, checks=("debugger", "identity", "jailbreak")
        )
    ]


def testPack_whenGivenNoChecks_packsWithAConfigHoldingOnlyTheRequiredOnes(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configs: list[object] = []

    def fake_pack(*, config: object, **_: object) -> identity.AppIdentity:
        configs.append(config)
        return _IDENTITY

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
        checks=[],
    )

    assert configs == [
        runtime_config.RuntimeConfig(build_id=_BUILD_ID, checks=("identity",))
    ]


def testPack_whenChecksAreNotOfThePlatform_packsWithTheOthersAndReportsThem(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configs: list[object] = []

    def fake_pack(*, config: object, **_: object) -> identity.AppIdentity:
        configs.append(config)
        return _IDENTITY

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    result = packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
        checks=["hooks", "root", "telepathy"],
    )

    assert configs == [
        runtime_config.RuntimeConfig(build_id=_BUILD_ID, checks=("hooks", "identity"))
    ]
    assert result.skipped_checks == ("root", "telepathy")


def testPack_whenOutputExists_raisesOutputExistsError(tmp_path: pathlib.Path) -> None:
    output = tmp_path / "out.ipa"
    output.write_bytes(b"")

    with pytest.raises(errors.OutputExistsError):
        packer.pack(
            app=tmp_path / "app.ipa",
            platform=platforms.Platform.IOS,
            output=output,
            build_id=_BUILD_ID,
            checks=["identity"],
        )


def testPack_whenAndroidApp_packsWithAConfigHoldingTheGivenBuildId(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.apk"
    app.write_bytes(b"an apk")
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, config: object, **_: object
    ) -> identity.AppIdentity:
        calls["app"] = app
        calls["output"] = output
        calls["config"] = config
        return _IDENTITY

    monkeypatch.setattr(android_packer, "pack", fake_pack)
    packer.pack(
        app=app,
        platform=platforms.Platform.ANDROID,
        output=tmp_path / "out.apk",
        build_id=_BUILD_ID,
        checks=["identity"],
    )

    assert calls == {
        "app": app,
        "output": tmp_path / "out.apk",
        "config": runtime_config.RuntimeConfig(
            build_id=_BUILD_ID, checks=("identity",)
        ),
    }


def testPack_whenAndroidApp_returnsTheProtectedAppItsIdentityAndTheBuildId(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.apk"
    app.write_bytes(b"an apk")
    monkeypatch.setattr(android_packer, "pack", lambda **_: _IDENTITY)

    result = packer.pack(
        app=app,
        platform=platforms.Platform.ANDROID,
        output=tmp_path / "out.apk",
        build_id=_BUILD_ID,
        checks=["identity"],
    )

    assert result == packer.PackResult(
        output=tmp_path / "out.apk",
        package_name="dev.ostorlab.demo",
        version="1.2.3",
        build_id=_BUILD_ID,
        skipped_checks=(),
    )
