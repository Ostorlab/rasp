"""Tests of the packer's entry point."""

import pathlib

import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import packer
from rasp_packer import platforms
from rasp_packer.ios import packer as ios_packer

_BUILD_ID = "a" * 64
_IDENTITY = identity.AppIdentity(package_name="dev.ostorlab.demo", version="1.2.3")


def testPack_whenAndroidApp_raisesUnsupportedPlatformError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.UnsupportedPlatformError, match="android"):
        packer.pack(
            app=tmp_path / "app.apk",
            platform=platforms.Platform.ANDROID,
            output=tmp_path / "out.apk",
            build_id=_BUILD_ID,
        )


def testPack_whenIosApp_packsWithTheGivenBuildId(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, build_id: object, **_: object
    ) -> identity.AppIdentity:
        calls["app"] = app
        calls["output"] = output
        calls["build_id"] = build_id
        return _IDENTITY

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
    )

    assert calls == {
        "app": ipa_file,
        "output": tmp_path / "out.ipa",
        "build_id": _BUILD_ID,
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
    )

    assert result == packer.PackResult(
        output=tmp_path / "out.ipa",
        package_name="dev.ostorlab.demo",
        version="1.2.3",
        build_id=_BUILD_ID,
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
        )


def testPack_whenOutputExists_raisesOutputExistsError(tmp_path: pathlib.Path) -> None:
    output = tmp_path / "out.ipa"
    output.write_bytes(b"")

    with pytest.raises(errors.OutputExistsError):
        packer.pack(
            app=tmp_path / "app.ipa",
            platform=platforms.Platform.IOS,
            output=output,
            build_id=_BUILD_ID,
        )
