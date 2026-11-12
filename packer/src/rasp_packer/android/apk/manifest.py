"""Reading and editing the app's manifest, on top of the binary XML editor.

This is the semantic layer over axml: it speaks in the app's component factory,
its package, its version and its minimum API level, and raises the packer's own
error types.
"""

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.android import capture_permissions
from rasp_packer.android.apk import axml


def ensure_capture_permissions(data: bytes, checks: tuple[str, ...]) -> bytes:
    """Add selected normal capture permissions without widening an existing restricted declaration."""
    for permission in capture_permissions.selected(checks):
        try:
            data = axml.ensure_uses_permission(data, permission)
        except axml.AxmlError as error:
            raise errors.ManifestError(str(error)) from error
    return data


def app_identity(manifest: bytes) -> identity.AppIdentity:
    """Returns who the app is: the package and the android:versionName of <manifest>.

    Args:
        manifest: The binary AndroidManifest.xml.

    Returns:
        The app's package name and version.

    Raises:
        ManifestError: The manifest cannot be read.
        InvalidApkError: The manifest has no package, or no literal android:versionName.
    """
    try:
        package = axml.read_manifest_package(manifest)
        version = axml.read_version_name(manifest)
    except axml.AxmlError as error:
        raise errors.ManifestError(str(error)) from error
    if package is None or package == "":
        raise errors.InvalidApkError("the app's manifest has no package")
    if version is None or version == "":
        raise errors.InvalidApkError(
            "the app's manifest has no literal android:versionName"
        )
    return identity.AppIdentity(package_name=package, version=version)


def app_component_factory(manifest: bytes) -> str | None:
    """Returns the app's declared android:appComponentFactory, or None when it has none.

    Args:
        manifest: The binary AndroidManifest.xml.

    Returns:
        The component factory class, or None.

    Raises:
        ManifestError: The manifest cannot be read.
    """
    try:
        return axml.read_app_component_factory(manifest)
    except axml.AxmlError as error:
        raise errors.ManifestError(str(error)) from error


def set_app_component_factory(manifest: bytes, class_name: str) -> bytes:
    """Returns the manifest with its android:appComponentFactory set to class_name.

    If <application> already declares the attribute, its value is replaced;
    otherwise the attribute is added. The input is not modified.

    Args:
        manifest: The binary AndroidManifest.xml.
        class_name: The fully qualified component factory to set.

    Returns:
        The edited binary AndroidManifest.xml.

    Raises:
        ManifestError: The manifest cannot be edited.
    """
    try:
        return axml.set_app_component_factory(manifest, class_name)
    except axml.AxmlError as error:
        raise errors.ManifestError(str(error)) from error


def raise_min_sdk_version(manifest: bytes, minimum: int) -> bytes:
    """Returns the manifest with its android:minSdkVersion raised to minimum, when it is lower.

    A manifest that already declares minimum or more is returned as it is. The
    input is not modified.

    Args:
        manifest: The binary AndroidManifest.xml.
        minimum: The lowest API level the protected app may declare.

    Returns:
        The binary AndroidManifest.xml, edited when its minSdkVersion was lower.

    Raises:
        ManifestError: The manifest cannot be read or edited.
        InvalidApkError: The manifest has no literal android:minSdkVersion.
    """
    try:
        declared = axml.read_min_sdk_version(manifest)
    except axml.AxmlError as error:
        raise errors.ManifestError(str(error)) from error
    if declared is None:
        raise errors.InvalidApkError(
            "the app's manifest has no literal android:minSdkVersion"
        )
    if declared >= minimum:
        return manifest
    try:
        return axml.set_min_sdk_version(manifest, minimum)
    except axml.AxmlError as error:
        raise errors.ManifestError(str(error)) from error
