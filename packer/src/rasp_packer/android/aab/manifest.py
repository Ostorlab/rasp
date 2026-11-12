"""Reading and editing the AAB's protobuf manifest.

This is the semantic layer over proto_manifest: it speaks in the app's component
factory, its package, its version and its minimum API level, and raises the
packer's own error types.  The interface mirrors ``apk.manifest`` so the packer
can treat both formats uniformly.
"""

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.android import capture_permissions
from rasp_packer.android.aab import proto_manifest


def ensure_capture_permissions(data: bytes, checks: tuple[str, ...]) -> bytes:
    """Add only selected normal capture permissions to the base protobuf manifest."""
    for permission in capture_permissions.selected(checks):
        try:
            data = proto_manifest.ensure_uses_permission(data, permission)
        except proto_manifest.ProtoManifestError as error:
            raise errors.ManifestError(str(error)) from error
    return data


def app_identity(manifest: bytes) -> identity.AppIdentity:
    """Return the app's package name and version from the proto manifest.

    Args:
        manifest: The proto-encoded AndroidManifest.xml.

    Returns:
        The app's package name and version.

    Raises:
        ManifestError: The manifest cannot be parsed.
        InvalidAabError: The manifest has no package or no literal versionName.
    """
    try:
        package = proto_manifest.read_package(manifest)
        version = proto_manifest.read_version_name(manifest)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error
    if package is None or package == "":
        raise errors.InvalidAabError("the app's manifest has no package")
    if version is None or version == "":
        raise errors.InvalidAabError(
            "the app's manifest has no literal android:versionName"
        )
    return identity.AppIdentity(package_name=package, version=version)


def app_component_factory(manifest: bytes) -> str | None:
    """Return the app's declared ``android:appComponentFactory``, or ``None``.

    Args:
        manifest: The proto-encoded AndroidManifest.xml.

    Returns:
        The component factory class, or ``None``.

    Raises:
        ManifestError: The manifest cannot be parsed.
    """
    try:
        return proto_manifest.read_app_component_factory(manifest)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error


def set_app_component_factory(manifest: bytes, class_name: str) -> bytes:
    """Return the manifest with ``android:appComponentFactory`` set to *class_name*.

    If ``<application>`` already declares the attribute, its value is replaced;
    otherwise the attribute is added.  The input is not modified.

    Args:
        manifest: The proto-encoded AndroidManifest.xml.
        class_name: The fully qualified component factory to set.

    Returns:
        The edited proto-encoded AndroidManifest.xml.

    Raises:
        ManifestError: The manifest cannot be edited.
    """
    try:
        return proto_manifest.set_app_component_factory(manifest, class_name)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error


def raise_min_sdk_version(manifest: bytes, minimum: int) -> bytes:
    """Return the manifest with ``android:minSdkVersion`` raised to *minimum*.

    A manifest that already declares *minimum* or higher is returned unchanged.

    Args:
        manifest: The proto-encoded AndroidManifest.xml.
        minimum: The lowest API level the protected app may declare.

    Returns:
        The proto-encoded AndroidManifest.xml, edited when minSdkVersion was lower.

    Raises:
        ManifestError: The manifest cannot be read or edited.
        InvalidAabError: The manifest has no literal android:minSdkVersion.
    """
    try:
        declared = proto_manifest.read_min_sdk_version(manifest)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error
    if declared is None:
        raise errors.InvalidAabError(
            "the app's manifest has no literal android:minSdkVersion"
        )
    if declared >= minimum:
        return manifest
    try:
        return proto_manifest.set_min_sdk_version(manifest, minimum)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error


def add_package_queries(manifest: bytes, packages: tuple[str, ...]) -> bytes:
    """Add only selected exact queries while preserving all host manifest declarations."""
    try:
        return proto_manifest.add_package_queries(manifest, packages)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error
