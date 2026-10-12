"""Reading and editing the app's manifest, on top of the binary XML editor.

This is the semantic layer over axml: it speaks in application classes and the
app package, and raises the packer's own error type.
"""

from rasp_packer import errors
from rasp_packer.android.apk import axml

DEFAULT_APPLICATION_CLASS = "android.app.Application"


def application_class(manifest: bytes) -> str:
    """Returns the app's application class, resolved to a fully qualified name.

    The class is read from the android:name attribute of <application>. The
    manifest may write it in a short form relative to the app package (for
    example ".MyApplication"); it is resolved against the package the way
    Android resolves it. If the app declares no application class, the Android
    default (android.app.Application) is returned.

    Args:
        manifest: The binary AndroidManifest.xml.

    Returns:
        The fully qualified application class.

    Raises:
        ManifestError: The manifest cannot be read.
    """
    try:
        declared = axml.read_application_class(manifest)
        if declared is None:
            return DEFAULT_APPLICATION_CLASS
        return _resolve(declared, axml.read_manifest_package(manifest))
    except axml.AxmlError as error:
        raise errors.ManifestError(str(error)) from error


def set_application_class(manifest: bytes, class_name: str) -> bytes:
    """Returns the manifest with its application class set to class_name.

    If <application> already has an android:name attribute, its value is
    replaced; otherwise the attribute is added. The input is not modified.

    Args:
        manifest: The binary AndroidManifest.xml.
        class_name: The fully qualified class to set.

    Returns:
        The edited binary AndroidManifest.xml.

    Raises:
        ManifestError: The manifest cannot be edited.
    """
    try:
        return axml.set_application_class(manifest, class_name)
    except axml.AxmlError as error:
        raise errors.ManifestError(str(error)) from error


def _resolve(class_name: str, package: str | None) -> str:
    """Resolves a manifest class name (".Name", "Name" or fully qualified) against the package."""
    if package is None:
        return class_name
    if class_name.startswith("."):
        return package + class_name
    if "." not in class_name:
        return f"{package}.{class_name}"
    return class_name
