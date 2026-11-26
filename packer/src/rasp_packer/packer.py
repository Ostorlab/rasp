"""The packer's entry point: protects a built app (APK, AAB, or IPA)."""

import collections.abc
import dataclasses
import pathlib
import re

from rasp_packer import archive_safety
from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import mapping as mapping_module
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import packer as ios_packer

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_JAVA_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


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
        checks: The ids of the check groups the protected app runs, as written into the app: the
            chosen groups of the platform and the required ones, each once, sorted.
        skipped_checks: The ids of the chosen check groups that are not groups of the platform,
            each once, in the order the caller gave them. The packer skipped them: the protected
            app does not run them.
        dropped_abis: The ABIs whose native libraries the packer removed from an Android app because
            they are not among the chosen ABIs, sorted. The protected app ships no native code for
            them.
    """

    output: pathlib.Path
    package_name: str
    version: str
    build_id: str
    checks: tuple[str, ...]
    skipped_checks: tuple[str, ...]
    dropped_abis: tuple[str, ...] = ()


def pack(
    *,
    app: pathlib.Path,
    platform: platforms.Platform,
    output: pathlib.Path,
    build_id: str,
    checks: collections.abc.Sequence[str],
    encrypt_packages: collections.abc.Sequence[str] = (),
    mapping: pathlib.Path | None = None,
    pin_certificate: pathlib.Path | None = None,
    abis: collections.abc.Sequence[str] | None = None,
) -> PackResult:
    """Protects a built app: adds the runtime and writes the protected app to `output`.

    The protected app is returned unsigned: the customer signs it before shipping it.

    The caller computes the build id. The packer writes it into the app as it is, in the
    runtime's config. The packer does not check the id's format: it only refuses an empty id or
    one with control characters.

    The caller chooses the check groups the protected app runs, from those of the platform in
    `checks.CHECKS`. The packer adds the required ones, `checks.REQUIRED_CHECKS`, and writes them
    sorted into the runtime's config. An empty choice runs only the required groups. The packer
    skips an id that is not one of the platform's groups and reports it in the result's
    `skipped_checks`, so that a caller still packs when it passes a group that was renamed or
    removed.

    The Android-only options are refused for an iOS app before any work: `mapping` and
    `pin_certificate`.

    Args:
        app: Path to the built app: an APK or AAB for Android, an IPA for iOS.
        platform: The platform of the app.
        output: Path to write the protected app to. It must not exist.
        build_id: The id of the protected build, written into the runtime's config.
        checks: The ids of the check groups the protected app runs. An empty sequence runs only
            the required groups. An id that is not one of the platform's groups is skipped.
        encrypt_packages: Extra Java packages to encrypt, besides the manifest package, named in
            original un-obfuscated form. Their classes are encrypted like the manifest package's,
            mapped through `mapping` the same way when given. Only Android apps have packages to
            encrypt: they are refused for iOS.
        mapping: The app's R8/ProGuard mapping file, for an Android release build R8 repackaged. It
            lets the packer find the app's own classes by their obfuscated names. Only Android apps
            have one: it is refused for iOS.
        pin_certificate: The certificate the developer will sign the protected app with, in PEM or
            DER form; the pack folds the certificate's digest into the key schedule, so a re-signed
            install derives a different key and nothing decrypts. None leaves the pack unpinned. Only
            Android apps are pinned: it is refused for iOS.
        abis: The ABIs the protected Android app supports. The packer removes the app's native
            libraries for every other ABI, reports those ABIs in the result's `dropped_abis`, and adds
            the runtime for the chosen ABIs only. None keeps the app's own ABIs. Only Android apps
            have ABIs: it is refused for iOS.

    Returns:
        The protected app, the app's package name and version, the build id, the check groups the
        app runs, the skipped check ids, and the dropped ABIs.

    Raises:
        InvalidBuildIdError: The build id is empty or has control characters.
        InvalidPackageError: A package name to encrypt is not a valid Java package name, or packages
            to encrypt were given for an iOS app.
        OutputExistsError: `output` already exists.
        DangerousAppError: The app archive holds an unsafe entry (encrypted, a symlink, or escaping
            its root), or cannot be read.
        InvalidAppError: The app file cannot be read.
        MappingError: A mapping file is given for an iOS app, or it cannot be read.
        InvalidCertificateError: A pinned certificate is given for an iOS app, or it cannot be read.
        InvalidAbisError: ABIs are given for an iOS app, or they cannot be packed; see the Android
            packer.
        Error: The app cannot be packed; see the platform's packer.
    """
    _refuse_android_options(
        platform,
        mapping=mapping,
        pin_certificate=pin_certificate,
        encrypt_packages=encrypt_packages,
        abis=abis,
    )
    _check_build_id(build_id)
    _check_packages(encrypt_packages)
    resolved_checks = check_groups.resolve_checks(platform, checks)
    if output.exists() is True:
        raise errors.OutputExistsError(f"{output} already exists")
    if archive_safety.is_dangerous(app) is True:
        raise errors.DangerousAppError(
            f"{app} holds an unsafe entry (encrypted, a symlink, or escaping the archive root), "
            "or cannot be read"
        )
    config = runtime_config.RuntimeConfig(
        build_id=build_id,
        checks=resolved_checks.checks,
        checks_mask=check_groups.checks_mask(platform, resolved_checks.checks),
    )
    app_identity: identity.AppIdentity
    dropped_abis: tuple[str, ...] = ()
    match platform:
        case platforms.Platform.ANDROID:
            android_result = android_packer.pack(
                app=app,
                output=output,
                config=config,
                mapping=mapping,
                encrypt_packages=encrypt_packages,
                pin_certificate=pin_certificate,
                abis=abis,
            )
            app_identity = android_result.app_identity
            dropped_abis = android_result.dropped_abis
        case platforms.Platform.IOS:
            app_identity = ios_packer.pack(app=app, output=output, config=config)
    return PackResult(
        output=output,
        package_name=app_identity.package_name,
        version=app_identity.version,
        build_id=build_id,
        checks=resolved_checks.checks,
        skipped_checks=resolved_checks.skipped,
        dropped_abis=dropped_abis,
    )


def default_output_path(app: pathlib.Path) -> pathlib.Path:
    """Returns the path a protected app is written to by default.

    The path sits next to the app and is named `<stem>-protected<suffix>`, so `dir/app.apk` gives
    `dir/app-protected.apk`.
    """
    return app.with_name(f"{app.stem}-protected{app.suffix}")


def _refuse_android_options(
    platform: platforms.Platform,
    *,
    mapping: pathlib.Path | None,
    pin_certificate: pathlib.Path | None,
    encrypt_packages: collections.abc.Sequence[str],
    abis: collections.abc.Sequence[str] | None,
) -> None:
    """Refuses the Android-only options for an app of another platform."""
    if platform is platforms.Platform.ANDROID:
        return
    if mapping is not None:
        raise mapping_module.MappingError("a mapping applies only to Android apps")
    if pin_certificate is not None:
        raise errors.InvalidCertificateError(
            "a pinned certificate applies only to Android apps"
        )
    if len(encrypt_packages) > 0:
        raise errors.InvalidPackageError(
            "packages to encrypt apply only to Android apps"
        )
    if abis is not None:
        raise errors.InvalidAbisError("ABIs apply only to Android apps")


def _check_build_id(build_id: str) -> None:
    """Refuses an empty build id, or one with control characters."""
    if len(build_id) == 0:
        raise errors.InvalidBuildIdError("the build id is empty")
    if _CONTROL_CHARACTERS.search(build_id) is not None:
        raise errors.InvalidBuildIdError(
            f"the build id {build_id!r} has control characters"
        )


def _check_packages(encrypt_packages: collections.abc.Sequence[str]) -> None:
    """Refuses a package to encrypt that is not a valid Java package name."""
    for package in encrypt_packages:
        if _JAVA_PACKAGE.fullmatch(package) is None:
            raise errors.InvalidPackageError(
                f"{package!r} is not a valid Java package name"
            )
