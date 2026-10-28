"""Editing the protobuf AndroidManifest.xml of a bundle module, the counterpart of axml for APKs.

A bundle stores every module's ``manifest/AndroidManifest.xml`` in the aapt2 protobuf form, not the
binary XML (AXML) an APK uses. The message is ``aapt.pb.XmlNode`` from the Android Open Source
Project's ``Resources.proto``; this module reads and edits it through the generated protobuf code,
never by hand.

The packer makes the same two edits it makes on an APK: it sets the application's
``android:appComponentFactory`` to the stub, and it raises the app's ``android:minSdkVersion``. Both
work on the parsed message and leave everything else untouched, so re-serializing a manifest that was
not changed reproduces the same bytes.

An attribute is found by its resource id, the stable key aapt gives a framework attribute (for
example ``android:minSdkVersion`` is ``0x0101020c``), the same ids axml matches on. Attribute order
does not matter here: bundletool sorts the attributes by resource id when it turns the module back
into an APK, so a new attribute is appended rather than inserted in order.
"""

from google.protobuf import message

from rasp_packer.android.aab.proto import Resources_pb2
from rasp_packer.android.apk import axml


class ProtoManifestError(Exception):
    """The bytes are not a protobuf AndroidManifest.xml this module can read or edit."""


def parse(data: bytes) -> Resources_pb2.XmlNode:
    """Parses the protobuf AndroidManifest.xml into its ``XmlNode`` message.

    Args:
        data: The protobuf AndroidManifest.xml.

    Returns:
        The parsed root node.

    Raises:
        ProtoManifestError: The bytes are not a parseable ``aapt.pb.XmlNode``.
    """
    node = Resources_pb2.XmlNode()
    try:
        node.ParseFromString(data)
    except message.DecodeError as error:
        raise ProtoManifestError(
            f"cannot parse the protobuf manifest: {error}"
        ) from error
    return node


def serialize(node: Resources_pb2.XmlNode) -> bytes:
    """Serializes the ``XmlNode`` message back to the protobuf AndroidManifest.xml bytes."""
    return node.SerializeToString()


def read_package(node: Resources_pb2.XmlNode) -> str | None:
    """Returns the ``package`` of ``<manifest>``, or None if it has none."""
    manifest = _manifest_element(node)
    for attribute in manifest.attribute:
        if attribute.namespace_uri == "" and attribute.name == axml.PACKAGE_ATTRIBUTE:
            return attribute.value
    return None


def read_version_name(node: Resources_pb2.XmlNode) -> str | None:
    """Returns the literal ``android:versionName`` of ``<manifest>``, or None if it has no literal one.

    A version name written as a resource reference has no literal string value, so it gives None, the
    same as axml does for an APK.
    """
    manifest = _manifest_element(node)
    attribute = _find_attribute(manifest, axml.ATTR_VERSION_NAME_RESOURCE_ID)
    if attribute is None or len(attribute.value) == 0:
        return None
    return attribute.value


def read_min_sdk_version(node: Resources_pb2.XmlNode) -> int | None:
    """Returns the literal ``android:minSdkVersion`` of ``<uses-sdk>``, or None if it has no literal one.

    A manifest without ``<uses-sdk>``, without the attribute, or with a value that is not a whole
    number (such as a resource reference) gives None.
    """
    uses_sdk = _find_child(_manifest_element(node), axml.USES_SDK_ELEMENT)
    if uses_sdk is None:
        return None
    attribute = _find_attribute(uses_sdk, axml.ATTR_MIN_SDK_VERSION_RESOURCE_ID)
    if attribute is None or attribute.HasField("compiled_item") is False:
        return None
    return _primitive_int(attribute.compiled_item)


def set_min_sdk_version(node: Resources_pb2.XmlNode, version: int) -> None:
    """Sets the ``android:minSdkVersion`` of ``<uses-sdk>`` to ``version``, in place.

    Raises:
        ProtoManifestError: The manifest has no ``<uses-sdk>`` with an ``android:minSdkVersion``.
    """
    uses_sdk = _find_child(_manifest_element(node), axml.USES_SDK_ELEMENT)
    attribute = (
        None
        if uses_sdk is None
        else _find_attribute(uses_sdk, axml.ATTR_MIN_SDK_VERSION_RESOURCE_ID)
    )
    if attribute is None:
        raise ProtoManifestError("manifest has no android:minSdkVersion on <uses-sdk>")
    attribute.value = str(version)
    attribute.compiled_item.prim.int_decimal_value = version


def read_app_component_factory(node: Resources_pb2.XmlNode) -> str | None:
    """Returns the ``android:appComponentFactory`` of ``<application>``, or None if it has none.

    Raises:
        ProtoManifestError: The manifest has no ``<application>``.
    """
    application = _application_element(node)
    attribute = _find_attribute(
        application, axml.ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
    )
    if attribute is None or len(attribute.value) == 0:
        return None
    return attribute.value


def set_app_component_factory(node: Resources_pb2.XmlNode, class_name: str) -> None:
    """Sets ``<application android:appComponentFactory>`` to ``class_name``, in place.

    If the application already declares the attribute, its value is replaced; otherwise the attribute
    is appended. The value is stored as a plain string, the way a compiled manifest stores
    ``android:versionName``.

    Raises:
        ProtoManifestError: The manifest has no ``<application>``.
    """
    application = _application_element(node)
    attribute = _find_attribute(
        application, axml.ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
    )
    if attribute is None:
        attribute = application.attribute.add()
        attribute.namespace_uri = axml.ANDROID_NAMESPACE
        attribute.name = axml.APP_COMPONENT_FACTORY_ATTRIBUTE
        attribute.resource_id = axml.ATTR_APP_COMPONENT_FACTORY_RESOURCE_ID
    attribute.ClearField("compiled_item")
    attribute.value = class_name


def _manifest_element(node: Resources_pb2.XmlNode) -> Resources_pb2.XmlElement:
    """Returns the root ``<manifest>`` element, or raises when the node is not one."""
    if node.WhichOneof("node") != "element":
        raise ProtoManifestError("the manifest's root node is not an element")
    if node.element.name != axml.MANIFEST_ELEMENT:
        raise ProtoManifestError(
            f"the manifest's root element is <{node.element.name}>, not <manifest>"
        )
    return node.element


def _application_element(node: Resources_pb2.XmlNode) -> Resources_pb2.XmlElement:
    """Returns the ``<application>`` element, or raises when there is none."""
    application = _find_child(_manifest_element(node), axml.APPLICATION_ELEMENT)
    if application is None:
        raise ProtoManifestError("manifest has no <application> element")
    return application


def _find_child(
    element: Resources_pb2.XmlElement, name: str
) -> Resources_pb2.XmlElement | None:
    """Returns the first child element named ``name``, or None when there is none."""
    for child in element.child:
        if child.WhichOneof("node") == "element" and child.element.name == name:
            return child.element
    return None


def _find_attribute(
    element: Resources_pb2.XmlElement, resource_id: int
) -> Resources_pb2.XmlAttribute | None:
    """Returns the element's attribute with ``resource_id``, or None when it has none."""
    for attribute in element.attribute:
        if attribute.resource_id == resource_id:
            return attribute
    return None


def _primitive_int(item: Resources_pb2.Item) -> int | None:
    """Returns the whole-number value of a compiled item, or None when it is not a decimal or hex int."""
    if item.WhichOneof("value") != "prim":
        return None
    primitive = item.prim
    which = primitive.WhichOneof("oneof_value")
    if which == "int_decimal_value":
        return primitive.int_decimal_value
    if which == "int_hexadecimal_value":
        return primitive.int_hexadecimal_value
    return None
