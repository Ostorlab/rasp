"""The platforms the packer protects apps for."""

import enum


@enum.unique
class Platform(enum.StrEnum):
    """A platform the runtime supports."""

    ANDROID = "android"
    IOS = "ios"


_EXTENSIONS: dict[Platform, tuple[str, ...]] = {
    Platform.ANDROID: (".apk", ".aab"),
    Platform.IOS: (".ipa",),
}


def extensions(platform: Platform) -> tuple[str, ...]:
    """Returns the lowercase file extensions of the platform's built apps, such as `.apk` and `.aab` for Android."""
    return _EXTENSIONS[platform]
