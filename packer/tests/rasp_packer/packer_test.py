"""Tests of the packer's entry point."""

import pathlib
import uuid

import pytest

from rasp_packer import errors
from rasp_packer import packer
from rasp_packer import platforms
from rasp_packer.ios import packer as ios_packer

_RASP_APP_ID = uuid.UUID("5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90")


def testPack_whenAndroidApp_raisesUnsupportedPlatformError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.UnsupportedPlatformError, match="android"):
        packer.pack(
            app=tmp_path / "app.apk",
            platform=platforms.Platform.ANDROID,
            output=tmp_path / "out.apk",
            rasp_app_id=_RASP_APP_ID,
        )


def testPack_whenIosApp_packsAndReturnsTheBuild(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, build: object, **_: object
    ) -> None:
        calls["app"] = app
        calls["output"] = output
        calls["build"] = build

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    result = packer.pack(
        app=tmp_path / "app.ipa",
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        rasp_app_id=_RASP_APP_ID,
    )

    assert result.output == tmp_path / "out.ipa"
    assert result.build.rasp_app_id == _RASP_APP_ID
    assert calls["app"] == tmp_path / "app.ipa"
    assert calls["build"] is result.build


def testPack_whenOutputExists_raisesOutputExistsError(tmp_path: pathlib.Path) -> None:
    output = tmp_path / "out.ipa"
    output.write_bytes(b"")

    with pytest.raises(errors.OutputExistsError):
        packer.pack(
            app=tmp_path / "app.ipa",
            platform=platforms.Platform.IOS,
            output=output,
            rasp_app_id=_RASP_APP_ID,
        )
