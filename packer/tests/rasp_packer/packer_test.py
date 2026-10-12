"""Tests of the packer's entry point."""

import hashlib
import pathlib
import uuid

import pytest

from rasp_packer import build
from rasp_packer import errors
from rasp_packer import packer
from rasp_packer import platforms
from rasp_packer import protection_versions
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import packer as ios_packer

_APPLICATION_ID = uuid.UUID("5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90")


def testPack_whenIosApp_packsAndReturnsTheBuildId(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, build_id: object, **_: object
    ) -> None:
        calls["app"] = app
        calls["output"] = output
        calls["build_id"] = build_id

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    result = packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        application_id=_APPLICATION_ID,
    )

    assert result.output == tmp_path / "out.ipa"
    assert calls["app"] == ipa_file
    assert calls["build_id"] == result.build_id


def testPack_whenIosApp_usesTheIosProtectionVersion(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ios_packer, "pack", lambda **_: None)
    monkeypatch.setattr(
        protection_versions,
        "PROTECTION_VERSIONS",
        {platforms.Platform.ANDROID: 3, platforms.Platform.IOS: 7},
    )
    result = packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        application_id=_APPLICATION_ID,
    )

    expected = build.compute_id(
        application_id=_APPLICATION_ID,
        app_digest=hashlib.sha256(ipa_file.read_bytes()).hexdigest(),
        platform=platforms.Platform.IOS,
        protection_version=7,
    )
    assert result.protection_version == 7
    assert result.build_id == expected


def testPack_whenAppIsMissing_raisesInvalidAppError(tmp_path: pathlib.Path) -> None:
    with pytest.raises(errors.InvalidAppError, match=r"app\.ipa"):
        packer.pack(
            app=tmp_path / "app.ipa",
            platform=platforms.Platform.IOS,
            output=tmp_path / "out.ipa",
            application_id=_APPLICATION_ID,
        )


def testPack_whenOutputExists_raisesOutputExistsError(tmp_path: pathlib.Path) -> None:
    output = tmp_path / "out.ipa"
    output.write_bytes(b"")

    with pytest.raises(errors.OutputExistsError):
        packer.pack(
            app=tmp_path / "app.ipa",
            platform=platforms.Platform.IOS,
            output=output,
            application_id=_APPLICATION_ID,
        )


def testPack_whenAndroidApp_packsAndReturnsTheBuildId(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.apk"
    app.write_bytes(b"an apk")
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, build_id: object, **_: object
    ) -> None:
        calls["app"] = app
        calls["output"] = output
        calls["build_id"] = build_id

    monkeypatch.setattr(android_packer, "pack", fake_pack)
    result = packer.pack(
        app=app,
        platform=platforms.Platform.ANDROID,
        output=tmp_path / "out.apk",
        application_id=_APPLICATION_ID,
    )

    assert result.output == tmp_path / "out.apk"
    assert calls["app"] == app
    assert calls["build_id"] == result.build_id


def testPack_whenAndroidApp_usesTheAndroidProtectionVersion(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.apk"
    app.write_bytes(b"an apk")
    monkeypatch.setattr(android_packer, "pack", lambda **_: None)
    monkeypatch.setattr(
        protection_versions,
        "PROTECTION_VERSIONS",
        {platforms.Platform.ANDROID: 3, platforms.Platform.IOS: 7},
    )
    result = packer.pack(
        app=app,
        platform=platforms.Platform.ANDROID,
        output=tmp_path / "out.apk",
        application_id=_APPLICATION_ID,
    )

    expected = build.compute_id(
        application_id=_APPLICATION_ID,
        app_digest=hashlib.sha256(b"an apk").hexdigest(),
        platform=platforms.Platform.ANDROID,
        protection_version=3,
    )
    assert result.protection_version == 3
    assert result.build_id == expected
