"""Reading and editing a bundle module's manifest, on top of the protobuf manifest editor.

This is the semantic layer over proto_manifest, the counterpart of apk.manifest for bundles: it speaks
in the app's component factory, package, version and minimum API level, and raises the packer's own
error types.
"""

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.android.aab import proto_manifest


def app_identity(manifest: bytes) -> identity.AppIdentity:
    """Returns who the app is: the package and the android:versionName of ``<manifest>``.

    Args:
        manifest: The protobuf AndroidManifest.xml.

    Returns:
        The app's package name and version.

    Raises:
        ManifestError: The manifest cannot be read.
        InvalidBundleError: The manifest has no package, or no literal android:versionName.
    """
    try:
        node = proto_manifest.parse(manifest)
        package = proto_manifest.read_package(node)
        version = proto_manifest.read_version_name(node)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error
    if package is None or package == "":
        raise errors.InvalidBundleError("the app's manifest has no package")
    if version is None or version == "":
        raise errors.InvalidBundleError(
            "the app's manifest has no literal android:versionName"
        )
    return identity.AppIdentity(package_name=package, version=version)


def app_component_factory(manifest: bytes) -> str | None:
    """Returns the app's declared android:appComponentFactory, or None when it has none.

    Args:
        manifest: The protobuf AndroidManifest.xml.

    Returns:
        The component factory class, or None.

    Raises:
        ManifestError: The manifest cannot be read.
    """
    try:
        node = proto_manifest.parse(manifest)
        return proto_manifest.read_app_component_factory(node)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error


def protect(manifest: bytes, *, factory: str, minimum_api_level: int) -> bytes:
    """Returns the manifest with the stub set as the component factory and the minSdk raised.

    The android:appComponentFactory is set to ``factory``. The android:minSdkVersion is raised to
    ``minimum_api_level`` when the declared value is lower, and left as it is when it already meets it.
    The input is not modified.

    Args:
        manifest: The protobuf AndroidManifest.xml.
        factory: The fully qualified component factory to set.
        minimum_api_level: The lowest API level the protected app may declare.

    Returns:
        The edited protobuf AndroidManifest.xml.

    Raises:
        ManifestError: The manifest cannot be read or edited.
        InvalidBundleError: The manifest has no literal android:minSdkVersion.
    """
    try:
        node = proto_manifest.parse(manifest)
        declared = proto_manifest.read_min_sdk_version(node)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error
    if declared is None:
        raise errors.InvalidBundleError(
            "the app's manifest has no literal android:minSdkVersion"
        )
    try:
        if declared < minimum_api_level:
            proto_manifest.set_min_sdk_version(node, minimum_api_level)
        proto_manifest.set_app_component_factory(node, factory)
        return proto_manifest.serialize(node)
    except proto_manifest.ProtoManifestError as error:
        raise errors.ManifestError(str(error)) from error
