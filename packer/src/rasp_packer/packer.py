"""The packer's entry point: protects a built app."""

import dataclasses
import pathlib
import uuid

from rasp_packer import build
from rasp_packer import errors
from rasp_packer import platforms
from rasp_packer.ios import packer as ios_packer


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PackResult:
    """What a pack produced.

    Attributes:
        output: Path to the protected app. It is unsigned: the customer signs it.
        build: The identity of the protected build, to register with the RASP registry.
    """

    output: pathlib.Path
    build: build.Build


def pack(
    *,
    app: pathlib.Path,
    platform: platforms.Platform,
    output: pathlib.Path,
    rasp_app_id: uuid.UUID,
) -> PackResult:
    """Protects a built app: adds the runtime and writes the protected app to `output`.

    The protected app is returned unsigned: the customer signs it before shipping it.

    Args:
        app: Path to the built app: an APK for Android, an IPA for iOS.
        platform: The platform of the app.
        output: Path to write the protected app to. It must not exist.
        rasp_app_id: Id of the protected app in the RASP registry.

    Returns:
        The protected app and the identity of the new build.

    Raises:
        OutputExistsError: `output` already exists.
        UnsupportedPlatformError: The packer cannot pack apps of this platform yet.
        Error: The app cannot be packed; see the platform's packer.
    """
    if output.exists() is True:
        raise errors.OutputExistsError(f"{output} already exists")
    new_build = build.Build.new(rasp_app_id)
    match platform:
        case platforms.Platform.IOS:
            ios_packer.pack(app=app, output=output, build=new_build)
        case platforms.Platform.ANDROID:
            raise errors.UnsupportedPlatformError(
                f"packing {platform} apps is not available yet"
            )
    return PackResult(output=output, build=new_build)
