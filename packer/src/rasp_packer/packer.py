"""The packer's entry point: protects a built app."""

import dataclasses
import hashlib
import pathlib
import uuid

from rasp_packer import build
from rasp_packer import errors
from rasp_packer import platforms
from rasp_packer import protection_versions
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import packer as ios_packer


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PackResult:
    """What a pack produced.

    Attributes:
        output: Path to the protected app. It is unsigned: the customer signs it.
        build_id: The deterministic id of the protected build, to register with the RASP registry.
        protection_version: The protection version of the app's platform the pack used.
    """

    output: pathlib.Path
    build_id: str
    protection_version: int


def pack(
    *,
    app: pathlib.Path,
    platform: platforms.Platform,
    output: pathlib.Path,
    application_id: uuid.UUID,
) -> PackResult:
    """Protects a built app: adds the runtime and writes the protected app to `output`.

    The protected app is returned unsigned: the customer signs it before shipping it.

    Args:
        app: Path to the built app: an APK for Android, an IPA for iOS.
        platform: The platform of the app.
        output: Path to write the protected app to. It must not exist.
        application_id: Id of the application in the RASP registry.

    Returns:
        The protected app, the build id, and the protection version used.

    Raises:
        OutputExistsError: `output` already exists.
        InvalidAppError: The app file cannot be read.
        Error: The app cannot be packed; see the platform's packer.
    """
    if output.exists() is True:
        raise errors.OutputExistsError(f"{output} already exists")
    protection_version = protection_versions.PROTECTION_VERSIONS[platform]
    build_id = build.compute_id(
        application_id=application_id,
        app_digest=_app_digest(app),
        platform=platform,
        protection_version=protection_version,
    )
    match platform:
        case platforms.Platform.ANDROID:
            android_packer.pack(app=app, output=output, build_id=build_id)
        case platforms.Platform.IOS:
            ios_packer.pack(app=app, output=output, build_id=build_id)
    return PackResult(
        output=output, build_id=build_id, protection_version=protection_version
    )


def _app_digest(app: pathlib.Path) -> str:
    """Returns the hex SHA-256 of the input app file's bytes."""
    try:
        with app.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError as error:
        raise errors.InvalidAppError(f"cannot read {app}: {error.strerror}") from error
