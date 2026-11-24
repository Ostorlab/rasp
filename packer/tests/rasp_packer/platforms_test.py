"""Tests of the platforms' app extensions."""

import pytest

from rasp_packer import platforms


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        (platforms.Platform.ANDROID, (".apk", ".aab")),
        (platforms.Platform.IOS, (".ipa",)),
    ],
)
def testExtensions_whenPlatformIsGiven_returnsTheExtensionsOfItsApps(
    platform: platforms.Platform, expected: tuple[str, ...]
) -> None:
    assert platforms.extensions(platform) == expected
