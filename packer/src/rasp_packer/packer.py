"""The packer's entry point: protects a built app (APK, AAB, or IPA)."""

import collections.abc
import dataclasses
import pathlib
import re

from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import packer as ios_packer

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PackResult:
    """What a pack produced.

    Attributes:
        output: Path to the protected app. It is unsigned: the customer signs it.
        package_name: The app's package name, read from the app: the manifest's package on Android,
            the bundle identifier on iOS.
        version: The app's version, read from the app: the manifest's `android:versionName` on
            Android, the short version string on iOS.
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
    checks: collections.abc.Sequence[str] | None = None,
) -> PackResult:
    """Protects a built app: adds the runtime and writes the protected app to `output`.

    The protected app is returned unsigned: the customer signs it before shipping it.

    The caller computes the build id. The packer writes it into the app as it is, in the
    runtime's config. The packer does not check the id's format: it only refuses an empty id or
    one with control characters.

    The caller can choose the check groups the protected app runs, from those of the platform in
    `checks.CHECKS`. The packer adds the required ones, `checks.REQUIRED_CHECKS`, and writes them
    sorted into the runtime's config. Without a choice, the config lists none and the app runs
    every group.

    Args:
        app: Path to the built app: an APK or AAB for Android, an IPA for iOS.
        platform: The platform of the app.
        output: Path to write the protected app to. It must not exist.
        build_id: The id of the protected build, written into the runtime's config.
        checks: The ids of the check groups the protected app runs. None runs every group.

    Returns:
        The protected app, the app's package name and version, and the build id.

    Raises:
        InvalidBuildIdError: The build id is empty or has control characters.
        UnknownCheckError: A check group is not one of the platform's.
        OutputExistsError: `output` already exists.
        InvalidAppError: The app file cannot be read.
        Error: The app cannot be packed; see the platform's packer.
    """
    _check_build_id(build_id)
    resolved_checks = (
        None if checks is None else check_groups.resolve_checks(platform, checks)
    )
    if output.exists() is True:
        raise errors.OutputExistsError(f"{output} already exists")
    config = runtime_config.RuntimeConfig(build_id=build_id, checks=resolved_checks)
    app_identity: identity.AppIdentity
    match platform:
        case platforms.Platform.ANDROID:
            app_identity = android_packer.pack(app=app, output=output, config=config)
        case platforms.Platform.IOS:
            app_identity = ios_packer.pack(app=app, output=output, config=config)
    return PackResult(
        output=output,
        package_name=app_identity.package_name,
        version=app_identity.version,
        build_id=build_id,
    )


def _check_build_id(build_id: str) -> None:
    """Refuses an empty build id, or one with control characters."""
    if len(build_id) == 0:
        raise errors.InvalidBuildIdError("the build id is empty")
    if _CONTROL_CHARACTERS.search(build_id) is not None:
        raise errors.InvalidBuildIdError(
            f"the build id {build_id!r} has control characters"
        )
