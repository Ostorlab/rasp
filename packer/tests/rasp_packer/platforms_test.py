"""Tests of the platform inference."""

import pathlib

import pytest

from rasp_packer import platforms


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("app.apk", platforms.Platform.ANDROID),
        ("app.aab", platforms.Platform.ANDROID),
        ("app.ipa", platforms.Platform.IOS),
        ("APP.APK", platforms.Platform.ANDROID),
        ("dir.v1/app.Ipa", platforms.Platform.IOS),
    ],
)
def testInfer_whenExtensionIsKnown_returnsThePlatform(
    name: str, expected: platforms.Platform
) -> None:
    """The platform follows the extension, whatever its case."""
    assert platforms.infer(pathlib.Path(name)) == expected


@pytest.mark.parametrize("name", ["app.zip", "app", "app.apk.bak"])
def testInfer_whenExtensionIsUnknown_raisesNamingTheAcceptedExtensions(
    name: str,
) -> None:
    """The error names the accepted extensions."""
    with pytest.raises(ValueError, match=r"\.apk, \.aab, \.ipa"):
        platforms.infer(pathlib.Path(name))
