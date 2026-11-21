"""Tests of the generated build id."""

import pathlib
import re

import pytest

from rasp_packer import build_ids
from rasp_packer import errors
from rasp_packer import platforms


@pytest.fixture
def app(tmp_path: pathlib.Path) -> pathlib.Path:
    """Returns a small app file."""
    path = tmp_path / "app.ipa"
    path.write_bytes(b"app bytes")
    return path


def testDefaultBuildId_whenGivenTheSameInputs_returnsTheSameHexSha256(
    app: pathlib.Path,
) -> None:
    """The same inputs give the same 64-character hex id."""
    first = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=["debugger"]
    )
    second = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=["debugger"]
    )

    assert first == second
    assert re.fullmatch(r"[0-9a-f]{64}", first) is not None


def testDefaultBuildId_whenChecksAreReorderedOrRepeated_returnsTheSameId(
    app: pathlib.Path,
) -> None:
    """The order and repeats of the checks, and unknown ones, do not change the id."""
    first = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=["debugger", "hooks"]
    )
    second = build_ids.default_build_id(
        app=app,
        platform=platforms.Platform.IOS,
        checks=["hooks", "debugger", "hooks", "unknown"],
    )

    assert first == second


def testDefaultBuildId_whenChecksChange_returnsAnotherId(app: pathlib.Path) -> None:
    """Another check gives another id."""
    first = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=["debugger"]
    )
    second = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=["hooks"]
    )

    assert first != second


def testDefaultBuildId_whenPlatformChanges_returnsAnotherId(app: pathlib.Path) -> None:
    """Another platform gives another id."""
    ios = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=["debugger"]
    )
    android = build_ids.default_build_id(
        app=app, platform=platforms.Platform.ANDROID, checks=["debugger"]
    )

    assert ios != android


def testDefaultBuildId_whenTheAppChanges_returnsAnotherId(app: pathlib.Path) -> None:
    """Other bytes in the app give another id."""
    before = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=[]
    )
    app.write_bytes(b"other bytes")

    after = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=[]
    )

    assert before != after


def testDefaultBuildId_whenTheAppIsMissing_raisesInvalidAppError(
    tmp_path: pathlib.Path,
) -> None:
    """An unreadable app raises InvalidAppError."""
    with pytest.raises(errors.InvalidAppError):
        build_ids.default_build_id(
            app=tmp_path / "missing.ipa", platform=platforms.Platform.IOS, checks=[]
        )


def testDefaultBuildId_whenActionsChange_returnsAnotherId(app: pathlib.Path) -> None:
    """Enforcement changes must not reuse the default id of the previous policy."""
    blocking = build_ids.default_build_id(
        app=app, platform=platforms.Platform.IOS, checks=["debugger"]
    )
    reporting = build_ids.default_build_id(
        app=app,
        platform=platforms.Platform.IOS,
        checks=["debugger"],
        report_only=["debugger"],
    )

    assert blocking != reporting
