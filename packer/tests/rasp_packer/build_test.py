"""Tests of the build identity."""

import uuid

from rasp_packer import build

_RASP_APP_ID = uuid.UUID("5f0c8a52-3f7e-4d0a-9b8e-2a6f1c4d7e90")


def testNew_whenCalled_keepsTheAppId() -> None:
    new_build = build.Build.new(_RASP_APP_ID)

    assert new_build.rasp_app_id == _RASP_APP_ID


def testNew_whenCalled_givesAUuid7BuildId() -> None:
    new_build = build.Build.new(_RASP_APP_ID)

    assert uuid.UUID(new_build.build_id).version == 7


def testNew_whenCalledTwice_givesDifferentBuildIds() -> None:
    first = build.Build.new(_RASP_APP_ID)
    second = build.Build.new(_RASP_APP_ID)

    assert first.build_id != second.build_id
