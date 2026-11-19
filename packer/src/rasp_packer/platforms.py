"""The platforms the packer protects apps for."""

import enum
import pathlib


@enum.unique
class Platform(enum.StrEnum):
    """A platform the runtime supports."""

    ANDROID = "android"
    IOS = "ios"


_EXTENSIONS: dict[str, Platform] = {
    ".apk": Platform.ANDROID,
    ".aab": Platform.ANDROID,
    ".ipa": Platform.IOS,
}


def accepted_extensions() -> list[str]:
    """Returns the app file extensions the platform can be inferred from, such as `.apk`."""
    return list(_EXTENSIONS)


def infer(app: pathlib.Path) -> Platform:
    """Infers the platform of an app from its file extension, ignoring the case.

    Raises:
        ValueError: The extension is not one of the accepted ones, and the message names them.
    """
    platform = _EXTENSIONS.get(app.suffix.lower())
    if platform is None:
        raise ValueError(
            f"cannot infer the platform from {app.name!r}, "
            f"the extension must be one of {', '.join(accepted_extensions())}; "
            "pass --platform"
        )
    return platform
