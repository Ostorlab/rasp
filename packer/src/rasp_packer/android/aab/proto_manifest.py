"""Low-level reader and editor for AAB protobuf-encoded AndroidManifest.xml.

An AAB manifest is a Protocol Buffer message using the AAPT2 ``XmlNode`` schema.
This module operates directly on the wire format so the packer does not depend
on compiled ``.proto`` definitions or the ``protobuf`` library.

Wire-format field map (only the fields the packer touches)::

    XmlNode (root)
      1: XmlElement
          1: NamespaceDeclaration (namespace_uri, prefix)
          3: name              (string — element tag, e.g. "manifest")
          4: XmlAttribute[]    (repeated)
              1: namespace_uri (string)
              2: name          (string)
              3: value         (string — literal text value)
              5: resource_id   (varint)
              6: Item (compiled_item)
                  7: Primitive
                      6: int_decimal_value  (varint)
          5: XmlNode[]         (child elements, wrapped in their own XmlNode)
      3: SourcePosition
"""

from __future__ import annotations

import dataclasses

from rasp_packer.android import capture_permissions

ANDROID_NS = "http://schemas.android.com/apk/res/android"

_FIELD_XML_ELEMENT = 1
_FIELD_ELEMENT_NAME = 3
_FIELD_ELEMENT_ATTR = 4
_FIELD_ELEMENT_CHILD = 5

_FIELD_ATTR_NAMESPACE = 1
_FIELD_ATTR_NAME = 2
_FIELD_ATTR_VALUE = 3
_FIELD_ATTR_RESOURCE_ID = 5
_FIELD_ATTR_COMPILED_ITEM = 6

_FIELD_ITEM_PRIMITIVE = 7
_FIELD_PRIMITIVE_INT = 6

_WIRE_VARINT = 0
_WIRE_LENGTH_DELIMITED = 2
_WIRE_FIXED32 = 5

_RESOURCE_ID_APP_COMPONENT_FACTORY = 0x0101057A
_RESOURCE_ID_MIN_SDK_VERSION = 0x101020C


def ensure_uses_permission(data: bytes, permission: str) -> bytes:
    """Insert one normal capture permission as a direct base manifest child; reject host restrictions."""
    if permission not in tuple(value for _, value in capture_permissions.PERMISSIONS):
        raise ProtoManifestError("unsupported capture permission")
    if len(data) > capture_permissions.MAX_MANIFEST_BYTES:
        raise ProtoManifestError("capture manifest exceeds bounds")
    roots = [
        field for field in _parse_fields(data) if field.number == _FIELD_XML_ELEMENT
    ]
    if len(roots) != 1 or not isinstance(roots[0].value, bytes):
        raise ProtoManifestError("capture manifest requires one root element")
    root = roots[0]
    assert isinstance(root.value, bytes)
    fields = _parse_fields(root.value)
    names = [field.value for field in fields if field.number == _FIELD_ELEMENT_NAME]
    if names != [b"manifest"]:
        raise ProtoManifestError("capture manifest root is not manifest")
    found = False
    for child in fields:
        if child.number != _FIELD_ELEMENT_CHILD:
            continue
        if not isinstance(child.value, bytes):
            raise ProtoManifestError("capture manifest child is not a node")
        elements = [
            field
            for field in _parse_fields(child.value)
            if field.number == _FIELD_XML_ELEMENT
        ]
        if len(elements) != 1 or not isinstance(elements[0].value, bytes):
            continue
        children = _parse_fields(elements[0].value)
        tags = [
            field.value for field in children if field.number == _FIELD_ELEMENT_NAME
        ]
        if tags not in (
            [b"uses-permission"],
            [b"uses-permission-sdk-23"],
            [b"uses-permission-sdk-m"],
        ):
            continue
        if _read_string_attr(children, "name", ANDROID_NS) != permission:
            continue
        attributes = [
            field for field in children if field.number == _FIELD_ELEMENT_ATTR
        ]
        if tags != [b"uses-permission"] or len(attributes) != 1:
            raise ProtoManifestError(
                f"selected capture permission is restricted: {permission}"
            )
        found = True
    if found is True:
        return data
    attribute = _build_string_attr(ANDROID_NS, "name", permission, 0x01010003)
    element = _encode_field(
        _FIELD_ELEMENT_NAME, _WIRE_LENGTH_DELIMITED, b"uses-permission"
    )
    element += _encode_field(_FIELD_ELEMENT_ATTR, _WIRE_LENGTH_DELIMITED, attribute)
    node = _encode_field(_FIELD_XML_ELEMENT, _WIRE_LENGTH_DELIMITED, element)
    addition = _encode_field(_FIELD_ELEMENT_CHILD, _WIRE_LENGTH_DELIMITED, node)
    rewritten = _encode_field(
        _FIELD_XML_ELEMENT, _WIRE_LENGTH_DELIMITED, root.value + addition
    )
    result = data[: root.start] + rewritten + data[root.end :]
    if len(result) > capture_permissions.MAX_MANIFEST_BYTES:
        raise ProtoManifestError("edited capture manifest exceeds bounds")
    return result


class ProtoManifestError(Exception):
    """The protobuf manifest bytes cannot be parsed or edited."""


def _decode_utf8(data: bytes) -> str:
    """Decode *data* as UTF-8, raising ``ProtoManifestError`` on invalid bytes."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtoManifestError(f"invalid utf-8 in manifest: {exc}") from exc


@dataclasses.dataclass(frozen=True, slots=True)
class _Field:
    """One parsed protobuf field."""

    number: int
    wire_type: int
    value: int | bytes
    start: int
    end: int


def _encode_varint(value: int) -> bytes:
    """Encode an unsigned integer as a protobuf varint."""
    parts: list[int] = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts)


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a varint starting at *pos*, returning ``(value, new_pos)``."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ProtoManifestError("truncated varint")
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7


def _parse_fields(data: bytes) -> list[_Field]:
    """Parse *data* into a flat list of protobuf fields."""
    pos = 0
    fields: list[_Field] = []
    while pos < len(data):
        start = pos
        tag, pos = _decode_varint(data, pos)
        number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == _WIRE_VARINT:
            int_val, pos = _decode_varint(data, pos)
            fields.append(
                _Field(
                    number=number,
                    wire_type=wire_type,
                    value=int_val,
                    start=start,
                    end=pos,
                )
            )
        elif wire_type == _WIRE_LENGTH_DELIMITED:
            length, pos = _decode_varint(data, pos)
            if pos + length > len(data):
                raise ProtoManifestError(
                    f"length-delimited field overruns buffer at offset {start}"
                )
            bytes_val = data[pos : pos + length]
            pos += length
            fields.append(
                _Field(
                    number=number,
                    wire_type=wire_type,
                    value=bytes_val,
                    start=start,
                    end=pos,
                )
            )
        elif wire_type == _WIRE_FIXED32:
            if pos + 4 > len(data):
                raise ProtoManifestError(
                    f"fixed32 field overruns buffer at offset {start}"
                )
            fixed_val = int.from_bytes(data[pos : pos + 4], "little")
            pos += 4
            fields.append(
                _Field(
                    number=number,
                    wire_type=wire_type,
                    value=fixed_val,
                    start=start,
                    end=pos,
                )
            )
        else:
            raise ProtoManifestError(
                f"unsupported wire type {wire_type} at offset {start}"
            )
    return fields


def _encode_field(number: int, wire_type: int, value: int | bytes) -> bytes:
    """Encode one protobuf field."""
    tag = _encode_varint((number << 3) | wire_type)
    if wire_type == _WIRE_VARINT:
        assert isinstance(value, int)
        return tag + _encode_varint(value)
    if wire_type == _WIRE_LENGTH_DELIMITED:
        assert isinstance(value, bytes)
        return tag + _encode_varint(len(value)) + value
    raise ProtoManifestError(f"_encode_field: unsupported wire type {wire_type}")


def _find_element(data: bytes, element_name: str) -> tuple[bytes, list[_Field]] | None:
    """Find the first ``XmlElement`` with the given tag name inside *data*.

    The proto layout is::

        Document: f1 = XmlElement (the root element)
        XmlElement: f1 = ns_decl, f3 = name, f4 = attrs, f5 = child XmlNodes
        Child XmlNode: f1 = XmlElement, f3 = SourcePosition

    Returns ``(element_bytes, element_fields)`` or ``None``.
    """
    for field in _parse_fields(data):
        if (
            field.number == _FIELD_XML_ELEMENT
            and field.wire_type == _WIRE_LENGTH_DELIMITED
        ):
            assert isinstance(field.value, bytes)
            el_fields = _parse_fields(field.value)
            for ef in el_fields:
                if (
                    ef.number == _FIELD_ELEMENT_NAME
                    and ef.wire_type == _WIRE_LENGTH_DELIMITED
                ):
                    assert isinstance(ef.value, bytes)
                    if _decode_utf8(ef.value) == element_name:
                        return field.value, el_fields
            for ef in el_fields:
                if (
                    ef.number == _FIELD_ELEMENT_CHILD
                    and ef.wire_type == _WIRE_LENGTH_DELIMITED
                ):
                    assert isinstance(ef.value, bytes)
                    result = _find_element(ef.value, element_name)
                    if result is not None:
                        return result
    return None


def _get_manifest_element(data: bytes) -> tuple[bytes, list[_Field]]:
    """Return the ``<manifest>`` XmlElement bytes and its parsed fields."""
    result = _find_element(data, "manifest")
    if result is None:
        raise ProtoManifestError("no <manifest> element in proto manifest")
    return result


def _get_application_element(data: bytes) -> tuple[bytes, list[_Field]]:
    """Return the ``<application>`` XmlElement bytes and its parsed fields."""
    result = _find_element(data, "application")
    if result is None:
        raise ProtoManifestError("no <application> element in proto manifest")
    return result


def _has_attr(fields: list[_Field], attr_name: str, namespace: str) -> bool:
    """Return whether the element has an attribute with the given name and namespace."""
    for field in fields:
        if (
            field.number != _FIELD_ELEMENT_ATTR
            or field.wire_type != _WIRE_LENGTH_DELIMITED
        ):
            continue
        assert isinstance(field.value, bytes)
        attr_fields = _parse_fields(field.value)
        name_match = False
        ns_match = False
        for af in attr_fields:
            if af.number == _FIELD_ATTR_NAME and af.wire_type == _WIRE_LENGTH_DELIMITED:
                assert isinstance(af.value, bytes)
                if _decode_utf8(af.value) == attr_name:
                    name_match = True
            if (
                af.number == _FIELD_ATTR_NAMESPACE
                and af.wire_type == _WIRE_LENGTH_DELIMITED
            ):
                assert isinstance(af.value, bytes)
                if _decode_utf8(af.value) == namespace:
                    ns_match = True
        if name_match is True and ns_match is True:
            return True
    return False


def _read_string_attr(
    fields: list[_Field], attr_name: str, namespace: str | None = None
) -> str | None:
    """Read the string value of a named attribute from element fields."""
    for field in fields:
        if (
            field.number != _FIELD_ELEMENT_ATTR
            or field.wire_type != _WIRE_LENGTH_DELIMITED
        ):
            continue
        assert isinstance(field.value, bytes)
        attr_fields = _parse_fields(field.value)
        name_match = False
        ns_match = namespace is None
        value: str | None = None
        for af in attr_fields:
            if af.number == _FIELD_ATTR_NAME and af.wire_type == _WIRE_LENGTH_DELIMITED:
                assert isinstance(af.value, bytes)
                if _decode_utf8(af.value) == attr_name:
                    name_match = True
            if (
                af.number == _FIELD_ATTR_NAMESPACE
                and af.wire_type == _WIRE_LENGTH_DELIMITED
            ):
                assert isinstance(af.value, bytes)
                if _decode_utf8(af.value) == namespace:
                    ns_match = True
            if (
                af.number == _FIELD_ATTR_VALUE
                and af.wire_type == _WIRE_LENGTH_DELIMITED
            ):
                assert isinstance(af.value, bytes)
                value = _decode_utf8(af.value)
        if name_match is True and ns_match is True:
            return value
    return None


def _read_int_attr(
    fields: list[_Field], attr_name: str, namespace: str | None = None
) -> int | None:
    """Read the integer value of a named attribute from element fields.

    Integer attributes are stored as ``compiled_item > Primitive > int_decimal_value``.
    """
    for field in fields:
        if (
            field.number != _FIELD_ELEMENT_ATTR
            or field.wire_type != _WIRE_LENGTH_DELIMITED
        ):
            continue
        assert isinstance(field.value, bytes)
        attr_fields = _parse_fields(field.value)
        name_match = False
        ns_match = namespace is None
        int_value: int | None = None
        for af in attr_fields:
            if af.number == _FIELD_ATTR_NAME and af.wire_type == _WIRE_LENGTH_DELIMITED:
                assert isinstance(af.value, bytes)
                if _decode_utf8(af.value) == attr_name:
                    name_match = True
            if (
                af.number == _FIELD_ATTR_NAMESPACE
                and af.wire_type == _WIRE_LENGTH_DELIMITED
            ):
                assert isinstance(af.value, bytes)
                if _decode_utf8(af.value) == namespace:
                    ns_match = True
            if (
                af.number == _FIELD_ATTR_COMPILED_ITEM
                and af.wire_type == _WIRE_LENGTH_DELIMITED
            ):
                assert isinstance(af.value, bytes)
                item_fields = _parse_fields(af.value)
                for item_f in item_fields:
                    if (
                        item_f.number == _FIELD_ITEM_PRIMITIVE
                        and item_f.wire_type == _WIRE_LENGTH_DELIMITED
                    ):
                        assert isinstance(item_f.value, bytes)
                        prim_fields = _parse_fields(item_f.value)
                        for pf in prim_fields:
                            if (
                                pf.number == _FIELD_PRIMITIVE_INT
                                and pf.wire_type == _WIRE_VARINT
                            ):
                                assert isinstance(pf.value, int)
                                int_value = pf.value
        if name_match is True and ns_match is True:
            return int_value
    return None


def _build_int_attr(namespace: str, name: str, value: int, resource_id: int) -> bytes:
    """Encode an XmlAttribute with an integer compiled value."""
    ns_field = _encode_field(
        _FIELD_ATTR_NAMESPACE, _WIRE_LENGTH_DELIMITED, namespace.encode("utf-8")
    )
    name_field = _encode_field(
        _FIELD_ATTR_NAME, _WIRE_LENGTH_DELIMITED, name.encode("utf-8")
    )
    res_field = _encode_field(_FIELD_ATTR_RESOURCE_ID, _WIRE_VARINT, resource_id)

    prim_inner = _encode_field(_FIELD_PRIMITIVE_INT, _WIRE_VARINT, value)
    prim_field = _encode_field(
        _FIELD_ITEM_PRIMITIVE, _WIRE_LENGTH_DELIMITED, prim_inner
    )
    item_field = _encode_field(
        _FIELD_ATTR_COMPILED_ITEM, _WIRE_LENGTH_DELIMITED, prim_field
    )

    return ns_field + name_field + res_field + item_field


def _build_string_attr(
    namespace: str, name: str, value: str, resource_id: int
) -> bytes:
    """Encode an XmlAttribute with a string value."""
    ns_field = _encode_field(
        _FIELD_ATTR_NAMESPACE, _WIRE_LENGTH_DELIMITED, namespace.encode("utf-8")
    )
    name_field = _encode_field(
        _FIELD_ATTR_NAME, _WIRE_LENGTH_DELIMITED, name.encode("utf-8")
    )
    val_field = _encode_field(
        _FIELD_ATTR_VALUE, _WIRE_LENGTH_DELIMITED, value.encode("utf-8")
    )
    res_field = _encode_field(_FIELD_ATTR_RESOURCE_ID, _WIRE_VARINT, resource_id)

    return ns_field + name_field + val_field + res_field


def _replace_element_in_manifest(
    manifest: bytes, old_element: bytes, new_element: bytes
) -> bytes:
    """Replace one XmlElement's content inside the manifest, preserving all other bytes."""
    return _replace_in_tree(manifest, old_element, new_element)


def _replace_in_tree(data: bytes, old_element: bytes, new_element: bytes) -> bytes:
    """Recursively find and replace *old_element* with *new_element* inside the proto tree.

    Walks the same ``XmlElement(f1) > children(f5) > XmlNode > XmlElement(f1)``
    structure as ``_find_element``.
    """
    fields = _parse_fields(data)
    result = bytearray()
    replaced = False

    for field in fields:
        if (
            replaced is False
            and field.number == _FIELD_XML_ELEMENT
            and field.wire_type == _WIRE_LENGTH_DELIMITED
        ):
            assert isinstance(field.value, bytes)
            if field.value == old_element:
                result.extend(_encode_field(field.number, field.wire_type, new_element))
                replaced = True
                continue
            new_el = _replace_children_in_element(field.value, old_element, new_element)
            if new_el != field.value:
                result.extend(_encode_field(field.number, field.wire_type, new_el))
                replaced = True
                continue

        result.extend(data[field.start : field.end])

    return bytes(result)


def _replace_children_in_element(
    element_bytes: bytes,
    old_element: bytes,
    new_element: bytes,
) -> bytes:
    """Walk the children (f5) of an XmlElement and replace *old_element*."""
    fields = _parse_fields(element_bytes)
    result = bytearray()
    replaced = False

    for field in fields:
        if (
            replaced is False
            and field.number == _FIELD_ELEMENT_CHILD
            and field.wire_type == _WIRE_LENGTH_DELIMITED
        ):
            assert isinstance(field.value, bytes)
            new_child = _replace_in_tree(field.value, old_element, new_element)
            if new_child != field.value:
                result.extend(_encode_field(field.number, field.wire_type, new_child))
                replaced = True
                continue

        result.extend(element_bytes[field.start : field.end])

    return bytes(result)


def _add_attr_to_element(element_bytes: bytes, attr_bytes: bytes) -> bytes:
    """Insert an XmlAttribute field before the first child element."""
    attr_field = _encode_field(_FIELD_ELEMENT_ATTR, _WIRE_LENGTH_DELIMITED, attr_bytes)
    fields = _parse_fields(element_bytes)
    result = bytearray()
    inserted = False
    for field in fields:
        if field.number == _FIELD_ELEMENT_CHILD and inserted is False:
            result.extend(attr_field)
            inserted = True
        result.extend(element_bytes[field.start : field.end])
    if inserted is False:
        result.extend(attr_field)
    return bytes(result)


def _replace_attr_in_element(
    element_bytes: bytes,
    attr_name: str,
    namespace: str,
    new_attr_bytes: bytes,
) -> bytes:
    """Replace one attribute by name inside an element, preserving the rest."""
    fields = _parse_fields(element_bytes)
    result = bytearray()

    for field in fields:
        if (
            field.number == _FIELD_ELEMENT_ATTR
            and field.wire_type == _WIRE_LENGTH_DELIMITED
        ):
            assert isinstance(field.value, bytes)
            af = _parse_fields(field.value)
            is_target = False
            for sub in af:
                if (
                    sub.number == _FIELD_ATTR_NAME
                    and sub.wire_type == _WIRE_LENGTH_DELIMITED
                ):
                    assert isinstance(sub.value, bytes)
                    if _decode_utf8(sub.value) == attr_name:
                        is_target = True
            if is_target is True:
                ns_ok = False
                for sub in af:
                    if (
                        sub.number == _FIELD_ATTR_NAMESPACE
                        and sub.wire_type == _WIRE_LENGTH_DELIMITED
                    ):
                        assert isinstance(sub.value, bytes)
                        if _decode_utf8(sub.value) == namespace:
                            ns_ok = True
                if ns_ok is True:
                    result.extend(
                        _encode_field(field.number, field.wire_type, new_attr_bytes)
                    )
                    continue
        result.extend(element_bytes[field.start : field.end])

    return bytes(result)


# ── Public API ──────────────────────────────────────────────────


def read_package(manifest: bytes) -> str | None:
    """Return the ``package`` attribute of the ``<manifest>`` element, or ``None``.

    Args:
        manifest: Raw proto-encoded AndroidManifest.xml bytes.

    Returns:
        The package name string, or ``None`` if the attribute is absent.

    Raises:
        ProtoManifestError: The manifest cannot be parsed.
    """
    _, el_fields = _get_manifest_element(manifest)
    return _read_string_attr(el_fields, "package")


def read_version_name(manifest: bytes) -> str | None:
    """Return the ``android:versionName`` from the ``<manifest>`` element, or ``None``.

    Args:
        manifest: Raw proto-encoded AndroidManifest.xml bytes.

    Returns:
        The version name string, or ``None`` if the attribute is absent.

    Raises:
        ProtoManifestError: The manifest cannot be parsed.
    """
    _, el_fields = _get_manifest_element(manifest)
    return _read_string_attr(el_fields, "versionName", namespace=ANDROID_NS)


def read_min_sdk_version(manifest: bytes) -> int | None:
    """Return the ``android:minSdkVersion`` from the ``<uses-sdk>`` element, or ``None``.

    Args:
        manifest: Raw proto-encoded AndroidManifest.xml bytes.

    Returns:
        The minimum SDK version integer, or ``None`` if the attribute is absent.

    Raises:
        ProtoManifestError: The manifest cannot be parsed.
    """
    result = _find_element(manifest, "uses-sdk")
    if result is None:
        return None
    _, el_fields = result
    return _read_int_attr(el_fields, "minSdkVersion", namespace=ANDROID_NS)


def set_min_sdk_version(manifest: bytes, version: int) -> bytes:
    """Return the manifest with ``android:minSdkVersion`` set to *version*.

    If ``<uses-sdk>`` already declares the attribute, its compiled value is
    replaced.  The input is not modified.

    Args:
        manifest: Raw proto-encoded AndroidManifest.xml bytes.
        version: The new minimum SDK version.

    Returns:
        The edited proto manifest bytes.

    Raises:
        ProtoManifestError: The manifest cannot be parsed or edited.
    """
    result = _find_element(manifest, "uses-sdk")
    if result is None:
        raise ProtoManifestError("no <uses-sdk> element in proto manifest")
    old_element, _ = result

    new_attr = _build_int_attr(
        ANDROID_NS, "minSdkVersion", version, _RESOURCE_ID_MIN_SDK_VERSION
    )
    new_element = _replace_attr_in_element(
        old_element, "minSdkVersion", ANDROID_NS, new_attr
    )
    if new_element == old_element:
        raise ProtoManifestError("no android:minSdkVersion on <uses-sdk>")
    return _replace_element_in_manifest(manifest, old_element, new_element)


def read_app_component_factory(manifest: bytes) -> str | None:
    """Return the ``android:appComponentFactory`` from ``<application>``, or ``None``.

    Args:
        manifest: Raw proto-encoded AndroidManifest.xml bytes.

    Returns:
        The component factory class name, or ``None`` if the attribute is absent.

    Raises:
        ProtoManifestError: The manifest cannot be parsed.
    """
    _, el_fields = _get_application_element(manifest)
    return _read_string_attr(el_fields, "appComponentFactory", namespace=ANDROID_NS)


def set_app_component_factory(manifest: bytes, class_name: str) -> bytes:
    """Return the manifest with ``android:appComponentFactory`` set to *class_name*.

    If ``<application>`` already declares the attribute, its value is replaced;
    otherwise the attribute is added.  The input is not modified.

    Args:
        manifest: Raw proto-encoded AndroidManifest.xml bytes.
        class_name: The fully qualified component factory class.

    Returns:
        The edited proto manifest bytes.

    Raises:
        ProtoManifestError: The manifest cannot be parsed or edited.
    """
    old_element, el_fields = _get_application_element(manifest)

    has_existing = _has_attr(el_fields, "appComponentFactory", ANDROID_NS)
    new_attr = _build_string_attr(
        ANDROID_NS,
        "appComponentFactory",
        class_name,
        _RESOURCE_ID_APP_COMPONENT_FACTORY,
    )

    if has_existing is True:
        new_element = _replace_attr_in_element(
            old_element, "appComponentFactory", ANDROID_NS, new_attr
        )
    else:
        new_element = _add_attr_to_element(old_element, new_attr)

    return _replace_element_in_manifest(manifest, old_element, new_element)
