"""The packer's entry point: protects a built app."""

import dataclasses
import pathlib
import re

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import platforms
from rasp_packer.ios import packer as ios_packer

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PackResult:
    """What a pack produced.

    Attributes:
        output: Path to the protected app. It is unsigned: the customer signs it.
        package_name: The app's package name, read from the app: the bundle identifier on iOS.
        version: The app's version, read from the app: the short version string on iOS.
        build_id: The id of the protected build, as written into the app.
    """

    output: pathlib.Path
    package_name: str
    version: str
    build_id: str


def pack(
    *,
    app: pathlib.Path,
    platform: platforms.Platform,
    output: pathlib.Path,
    build_id: str,
) -> PackResult:
    """Protects a built app: adds the runtime and writes the protected app to `output`.

    The protected app is returned unsigned: the customer signs it before shipping it.

    The caller computes the build id and the packer writes it into the app as it is. The
    packer does not check the id's format: it only refuses an id it cannot write.

    Args:
        app: Path to the built app: an APK for Android, an IPA for iOS.
        platform: The platform of the app.
        output: Path to write the protected app to. It must not exist.
        build_id: The id of the protected build, written into the app.

    Returns:
        The protected app, the app's package name and version, and the build id.

    Raises:
        InvalidBuildIdError: The build id is empty or has control characters.
        OutputExistsError: `output` already exists.
        UnsupportedPlatformError: The packer cannot pack apps of this platform yet.
        InvalidAppError: The app file cannot be read.
        Error: The app cannot be packed; see the platform's packer.
    """
    _check_build_id(build_id)
    if output.exists() is True:
        raise errors.OutputExistsError(f"{output} already exists")
    if platform is platforms.Platform.ANDROID:
        raise errors.UnsupportedPlatformError(
            f"packing {platform} apps is not available yet"
        )
    app_identity: identity.AppIdentity
    match platform:
        case platforms.Platform.IOS:
            app_identity = ios_packer.pack(app=app, output=output, build_id=build_id)
    return PackResult(
        output=output,
        package_name=app_identity.package_name,
        version=app_identity.version,
        build_id=build_id,
    )


def _check_build_id(build_id: str) -> None:
    """Refuses a build id the packer cannot write: an empty one, or one an XML plist cannot hold."""
    if len(build_id) == 0:
        raise errors.InvalidBuildIdError("the build id is empty")
    if _CONTROL_CHARACTERS.search(build_id) is not None:
        raise errors.InvalidBuildIdError(
            f"the build id {build_id!r} has control characters"
        )
