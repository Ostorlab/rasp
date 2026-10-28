from rasp_packer.android.aab.proto import Configuration_pb2 as _Configuration_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AllowNew(_message.Message):
    __slots__ = ["comment", "source"]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    comment: str
    source: Source
    def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ...) -> None: ...

class Array(_message.Message):
    __slots__ = ["element"]
    class Element(_message.Message):
        __slots__ = ["comment", "item", "source"]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        ITEM_FIELD_NUMBER: _ClassVar[int]
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        comment: str
        item: Item
        source: Source
        def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ..., item: _Optional[_Union[Item, _Mapping]] = ...) -> None: ...
    ELEMENT_FIELD_NUMBER: _ClassVar[int]
    element: _containers.RepeatedCompositeFieldContainer[Array.Element]
    def __init__(self, element: _Optional[_Iterable[_Union[Array.Element, _Mapping]]] = ...) -> None: ...

class Attribute(_message.Message):
    __slots__ = ["format_flags", "max_int", "min_int", "symbol"]
    class FormatFlags(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class Symbol(_message.Message):
        __slots__ = ["comment", "name", "source", "type", "value"]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        NAME_FIELD_NUMBER: _ClassVar[int]
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        comment: str
        name: Reference
        source: Source
        type: int
        value: int
        def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ..., name: _Optional[_Union[Reference, _Mapping]] = ..., value: _Optional[int] = ..., type: _Optional[int] = ...) -> None: ...
    ANY: Attribute.FormatFlags
    BOOLEAN: Attribute.FormatFlags
    COLOR: Attribute.FormatFlags
    DIMENSION: Attribute.FormatFlags
    ENUM: Attribute.FormatFlags
    FLAGS: Attribute.FormatFlags
    FLOAT: Attribute.FormatFlags
    FORMAT_FLAGS_FIELD_NUMBER: _ClassVar[int]
    FRACTION: Attribute.FormatFlags
    INTEGER: Attribute.FormatFlags
    MAX_INT_FIELD_NUMBER: _ClassVar[int]
    MIN_INT_FIELD_NUMBER: _ClassVar[int]
    NONE: Attribute.FormatFlags
    REFERENCE: Attribute.FormatFlags
    STRING: Attribute.FormatFlags
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    format_flags: int
    max_int: int
    min_int: int
    symbol: _containers.RepeatedCompositeFieldContainer[Attribute.Symbol]
    def __init__(self, format_flags: _Optional[int] = ..., min_int: _Optional[int] = ..., max_int: _Optional[int] = ..., symbol: _Optional[_Iterable[_Union[Attribute.Symbol, _Mapping]]] = ...) -> None: ...

class CompoundValue(_message.Message):
    __slots__ = ["array", "attr", "plural", "style", "styleable"]
    ARRAY_FIELD_NUMBER: _ClassVar[int]
    ATTR_FIELD_NUMBER: _ClassVar[int]
    PLURAL_FIELD_NUMBER: _ClassVar[int]
    STYLEABLE_FIELD_NUMBER: _ClassVar[int]
    STYLE_FIELD_NUMBER: _ClassVar[int]
    array: Array
    attr: Attribute
    plural: Plural
    style: Style
    styleable: Styleable
    def __init__(self, attr: _Optional[_Union[Attribute, _Mapping]] = ..., style: _Optional[_Union[Style, _Mapping]] = ..., styleable: _Optional[_Union[Styleable, _Mapping]] = ..., array: _Optional[_Union[Array, _Mapping]] = ..., plural: _Optional[_Union[Plural, _Mapping]] = ...) -> None: ...

class ConfigValue(_message.Message):
    __slots__ = ["config", "value"]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    config: _Configuration_pb2.Configuration
    value: Value
    def __init__(self, config: _Optional[_Union[_Configuration_pb2.Configuration, _Mapping]] = ..., value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class Entry(_message.Message):
    __slots__ = ["allow_new", "config_value", "entry_id", "name", "overlayable_item", "visibility"]
    ALLOW_NEW_FIELD_NUMBER: _ClassVar[int]
    CONFIG_VALUE_FIELD_NUMBER: _ClassVar[int]
    ENTRY_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OVERLAYABLE_ITEM_FIELD_NUMBER: _ClassVar[int]
    VISIBILITY_FIELD_NUMBER: _ClassVar[int]
    allow_new: AllowNew
    config_value: _containers.RepeatedCompositeFieldContainer[ConfigValue]
    entry_id: EntryId
    name: str
    overlayable_item: OverlayableItem
    visibility: Visibility
    def __init__(self, entry_id: _Optional[_Union[EntryId, _Mapping]] = ..., name: _Optional[str] = ..., visibility: _Optional[_Union[Visibility, _Mapping]] = ..., allow_new: _Optional[_Union[AllowNew, _Mapping]] = ..., overlayable_item: _Optional[_Union[OverlayableItem, _Mapping]] = ..., config_value: _Optional[_Iterable[_Union[ConfigValue, _Mapping]]] = ...) -> None: ...

class EntryId(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class FileReference(_message.Message):
    __slots__ = ["path", "type"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    BINARY_XML: FileReference.Type
    PATH_FIELD_NUMBER: _ClassVar[int]
    PNG: FileReference.Type
    PROTO_XML: FileReference.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN: FileReference.Type
    path: str
    type: FileReference.Type
    def __init__(self, path: _Optional[str] = ..., type: _Optional[_Union[FileReference.Type, str]] = ...) -> None: ...

class Id(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class Item(_message.Message):
    __slots__ = ["file", "id", "prim", "raw_str", "ref", "str", "styled_str"]
    FILE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    PRIM_FIELD_NUMBER: _ClassVar[int]
    RAW_STR_FIELD_NUMBER: _ClassVar[int]
    REF_FIELD_NUMBER: _ClassVar[int]
    STR_FIELD_NUMBER: _ClassVar[int]
    STYLED_STR_FIELD_NUMBER: _ClassVar[int]
    file: FileReference
    id: Id
    prim: Primitive
    raw_str: RawString
    ref: Reference
    str: String
    styled_str: StyledString
    def __init__(self, ref: _Optional[_Union[Reference, _Mapping]] = ..., str: _Optional[_Union[String, _Mapping]] = ..., raw_str: _Optional[_Union[RawString, _Mapping]] = ..., styled_str: _Optional[_Union[StyledString, _Mapping]] = ..., file: _Optional[_Union[FileReference, _Mapping]] = ..., id: _Optional[_Union[Id, _Mapping]] = ..., prim: _Optional[_Union[Primitive, _Mapping]] = ...) -> None: ...

class Overlayable(_message.Message):
    __slots__ = ["actor", "name", "source"]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    actor: str
    name: str
    source: Source
    def __init__(self, name: _Optional[str] = ..., source: _Optional[_Union[Source, _Mapping]] = ..., actor: _Optional[str] = ...) -> None: ...

class OverlayableItem(_message.Message):
    __slots__ = ["comment", "overlayable_idx", "policy", "source"]
    class Policy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    NONE: OverlayableItem.Policy
    ODM: OverlayableItem.Policy
    OEM: OverlayableItem.Policy
    OVERLAYABLE_IDX_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    PRODUCT: OverlayableItem.Policy
    PUBLIC: OverlayableItem.Policy
    SIGNATURE: OverlayableItem.Policy
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    SYSTEM: OverlayableItem.Policy
    VENDOR: OverlayableItem.Policy
    comment: str
    overlayable_idx: int
    policy: _containers.RepeatedScalarFieldContainer[OverlayableItem.Policy]
    source: Source
    def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ..., policy: _Optional[_Iterable[_Union[OverlayableItem.Policy, str]]] = ..., overlayable_idx: _Optional[int] = ...) -> None: ...

class Package(_message.Message):
    __slots__ = ["package_id", "package_name", "type"]
    PACKAGE_ID_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    package_id: PackageId
    package_name: str
    type: _containers.RepeatedCompositeFieldContainer[Type]
    def __init__(self, package_id: _Optional[_Union[PackageId, _Mapping]] = ..., package_name: _Optional[str] = ..., type: _Optional[_Iterable[_Union[Type, _Mapping]]] = ...) -> None: ...

class PackageId(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class Plural(_message.Message):
    __slots__ = ["entry"]
    class Arity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class Entry(_message.Message):
        __slots__ = ["arity", "comment", "item", "source"]
        ARITY_FIELD_NUMBER: _ClassVar[int]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        ITEM_FIELD_NUMBER: _ClassVar[int]
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        arity: Plural.Arity
        comment: str
        item: Item
        source: Source
        def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ..., arity: _Optional[_Union[Plural.Arity, str]] = ..., item: _Optional[_Union[Item, _Mapping]] = ...) -> None: ...
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    FEW: Plural.Arity
    MANY: Plural.Arity
    ONE: Plural.Arity
    OTHER: Plural.Arity
    TWO: Plural.Arity
    ZERO: Plural.Arity
    entry: _containers.RepeatedCompositeFieldContainer[Plural.Entry]
    def __init__(self, entry: _Optional[_Iterable[_Union[Plural.Entry, _Mapping]]] = ...) -> None: ...

class Primitive(_message.Message):
    __slots__ = ["boolean_value", "color_argb4_value", "color_argb8_value", "color_rgb4_value", "color_rgb8_value", "dimension_value", "dimension_value_deprecated", "empty_value", "float_value", "fraction_value", "fraction_value_deprecated", "int_decimal_value", "int_hexadecimal_value", "null_value"]
    class EmptyType(_message.Message):
        __slots__ = []
        def __init__(self) -> None: ...
    class NullType(_message.Message):
        __slots__ = []
        def __init__(self) -> None: ...
    BOOLEAN_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_ARGB4_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_ARGB8_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_RGB4_VALUE_FIELD_NUMBER: _ClassVar[int]
    COLOR_RGB8_VALUE_FIELD_NUMBER: _ClassVar[int]
    DIMENSION_VALUE_DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    DIMENSION_VALUE_FIELD_NUMBER: _ClassVar[int]
    EMPTY_VALUE_FIELD_NUMBER: _ClassVar[int]
    FLOAT_VALUE_FIELD_NUMBER: _ClassVar[int]
    FRACTION_VALUE_DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    FRACTION_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_DECIMAL_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_HEXADECIMAL_VALUE_FIELD_NUMBER: _ClassVar[int]
    NULL_VALUE_FIELD_NUMBER: _ClassVar[int]
    boolean_value: bool
    color_argb4_value: int
    color_argb8_value: int
    color_rgb4_value: int
    color_rgb8_value: int
    dimension_value: int
    dimension_value_deprecated: float
    empty_value: Primitive.EmptyType
    float_value: float
    fraction_value: int
    fraction_value_deprecated: float
    int_decimal_value: int
    int_hexadecimal_value: int
    null_value: Primitive.NullType
    def __init__(self, null_value: _Optional[_Union[Primitive.NullType, _Mapping]] = ..., empty_value: _Optional[_Union[Primitive.EmptyType, _Mapping]] = ..., float_value: _Optional[float] = ..., dimension_value: _Optional[int] = ..., fraction_value: _Optional[int] = ..., int_decimal_value: _Optional[int] = ..., int_hexadecimal_value: _Optional[int] = ..., boolean_value: bool = ..., color_argb8_value: _Optional[int] = ..., color_rgb8_value: _Optional[int] = ..., color_argb4_value: _Optional[int] = ..., color_rgb4_value: _Optional[int] = ..., dimension_value_deprecated: _Optional[float] = ..., fraction_value_deprecated: _Optional[float] = ...) -> None: ...

class RawString(_message.Message):
    __slots__ = ["value"]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: _Optional[str] = ...) -> None: ...

class Reference(_message.Message):
    __slots__ = ["id", "name", "private", "type"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    ATTRIBUTE: Reference.Type
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_FIELD_NUMBER: _ClassVar[int]
    REFERENCE: Reference.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    private: bool
    type: Reference.Type
    def __init__(self, type: _Optional[_Union[Reference.Type, str]] = ..., id: _Optional[int] = ..., name: _Optional[str] = ..., private: bool = ...) -> None: ...

class ResourceTable(_message.Message):
    __slots__ = ["overlayable", "package", "source_pool", "tool_fingerprint"]
    OVERLAYABLE_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_POOL_FIELD_NUMBER: _ClassVar[int]
    TOOL_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    overlayable: _containers.RepeatedCompositeFieldContainer[Overlayable]
    package: _containers.RepeatedCompositeFieldContainer[Package]
    source_pool: StringPool
    tool_fingerprint: _containers.RepeatedCompositeFieldContainer[ToolFingerprint]
    def __init__(self, source_pool: _Optional[_Union[StringPool, _Mapping]] = ..., package: _Optional[_Iterable[_Union[Package, _Mapping]]] = ..., overlayable: _Optional[_Iterable[_Union[Overlayable, _Mapping]]] = ..., tool_fingerprint: _Optional[_Iterable[_Union[ToolFingerprint, _Mapping]]] = ...) -> None: ...

class Source(_message.Message):
    __slots__ = ["path_idx", "position"]
    PATH_IDX_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    path_idx: int
    position: SourcePosition
    def __init__(self, path_idx: _Optional[int] = ..., position: _Optional[_Union[SourcePosition, _Mapping]] = ...) -> None: ...

class SourcePosition(_message.Message):
    __slots__ = ["column_number", "line_number"]
    COLUMN_NUMBER_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    column_number: int
    line_number: int
    def __init__(self, line_number: _Optional[int] = ..., column_number: _Optional[int] = ...) -> None: ...

class String(_message.Message):
    __slots__ = ["value"]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: _Optional[str] = ...) -> None: ...

class StringPool(_message.Message):
    __slots__ = ["data"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class Style(_message.Message):
    __slots__ = ["entry", "parent", "parent_source"]
    class Entry(_message.Message):
        __slots__ = ["comment", "item", "key", "source"]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        ITEM_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        comment: str
        item: Item
        key: Reference
        source: Source
        def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ..., key: _Optional[_Union[Reference, _Mapping]] = ..., item: _Optional[_Union[Item, _Mapping]] = ...) -> None: ...
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    PARENT_SOURCE_FIELD_NUMBER: _ClassVar[int]
    entry: _containers.RepeatedCompositeFieldContainer[Style.Entry]
    parent: Reference
    parent_source: Source
    def __init__(self, parent: _Optional[_Union[Reference, _Mapping]] = ..., parent_source: _Optional[_Union[Source, _Mapping]] = ..., entry: _Optional[_Iterable[_Union[Style.Entry, _Mapping]]] = ...) -> None: ...

class Styleable(_message.Message):
    __slots__ = ["entry"]
    class Entry(_message.Message):
        __slots__ = ["attr", "comment", "source"]
        ATTR_FIELD_NUMBER: _ClassVar[int]
        COMMENT_FIELD_NUMBER: _ClassVar[int]
        SOURCE_FIELD_NUMBER: _ClassVar[int]
        attr: Reference
        comment: str
        source: Source
        def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ..., attr: _Optional[_Union[Reference, _Mapping]] = ...) -> None: ...
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    entry: _containers.RepeatedCompositeFieldContainer[Styleable.Entry]
    def __init__(self, entry: _Optional[_Iterable[_Union[Styleable.Entry, _Mapping]]] = ...) -> None: ...

class StyledString(_message.Message):
    __slots__ = ["span", "value"]
    class Span(_message.Message):
        __slots__ = ["first_char", "last_char", "tag"]
        FIRST_CHAR_FIELD_NUMBER: _ClassVar[int]
        LAST_CHAR_FIELD_NUMBER: _ClassVar[int]
        TAG_FIELD_NUMBER: _ClassVar[int]
        first_char: int
        last_char: int
        tag: str
        def __init__(self, tag: _Optional[str] = ..., first_char: _Optional[int] = ..., last_char: _Optional[int] = ...) -> None: ...
    SPAN_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    span: _containers.RepeatedCompositeFieldContainer[StyledString.Span]
    value: str
    def __init__(self, value: _Optional[str] = ..., span: _Optional[_Iterable[_Union[StyledString.Span, _Mapping]]] = ...) -> None: ...

class ToolFingerprint(_message.Message):
    __slots__ = ["tool", "version"]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    tool: str
    version: str
    def __init__(self, tool: _Optional[str] = ..., version: _Optional[str] = ...) -> None: ...

class Type(_message.Message):
    __slots__ = ["entry", "name", "type_id"]
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_ID_FIELD_NUMBER: _ClassVar[int]
    entry: _containers.RepeatedCompositeFieldContainer[Entry]
    name: str
    type_id: TypeId
    def __init__(self, type_id: _Optional[_Union[TypeId, _Mapping]] = ..., name: _Optional[str] = ..., entry: _Optional[_Iterable[_Union[Entry, _Mapping]]] = ...) -> None: ...

class TypeId(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class Value(_message.Message):
    __slots__ = ["comment", "compound_value", "item", "source", "weak"]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    COMPOUND_VALUE_FIELD_NUMBER: _ClassVar[int]
    ITEM_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    WEAK_FIELD_NUMBER: _ClassVar[int]
    comment: str
    compound_value: CompoundValue
    item: Item
    source: Source
    weak: bool
    def __init__(self, source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ..., weak: bool = ..., item: _Optional[_Union[Item, _Mapping]] = ..., compound_value: _Optional[_Union[CompoundValue, _Mapping]] = ...) -> None: ...

class Visibility(_message.Message):
    __slots__ = ["comment", "level", "source"]
    class Level(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    PRIVATE: Visibility.Level
    PUBLIC: Visibility.Level
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN: Visibility.Level
    comment: str
    level: Visibility.Level
    source: Source
    def __init__(self, level: _Optional[_Union[Visibility.Level, str]] = ..., source: _Optional[_Union[Source, _Mapping]] = ..., comment: _Optional[str] = ...) -> None: ...

class XmlAttribute(_message.Message):
    __slots__ = ["compiled_item", "name", "namespace_uri", "resource_id", "source", "value"]
    COMPILED_ITEM_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_URI_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    compiled_item: Item
    name: str
    namespace_uri: str
    resource_id: int
    source: SourcePosition
    value: str
    def __init__(self, namespace_uri: _Optional[str] = ..., name: _Optional[str] = ..., value: _Optional[str] = ..., source: _Optional[_Union[SourcePosition, _Mapping]] = ..., resource_id: _Optional[int] = ..., compiled_item: _Optional[_Union[Item, _Mapping]] = ...) -> None: ...

class XmlElement(_message.Message):
    __slots__ = ["attribute", "child", "name", "namespace_declaration", "namespace_uri"]
    ATTRIBUTE_FIELD_NUMBER: _ClassVar[int]
    CHILD_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_DECLARATION_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_URI_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    attribute: _containers.RepeatedCompositeFieldContainer[XmlAttribute]
    child: _containers.RepeatedCompositeFieldContainer[XmlNode]
    name: str
    namespace_declaration: _containers.RepeatedCompositeFieldContainer[XmlNamespace]
    namespace_uri: str
    def __init__(self, namespace_declaration: _Optional[_Iterable[_Union[XmlNamespace, _Mapping]]] = ..., namespace_uri: _Optional[str] = ..., name: _Optional[str] = ..., attribute: _Optional[_Iterable[_Union[XmlAttribute, _Mapping]]] = ..., child: _Optional[_Iterable[_Union[XmlNode, _Mapping]]] = ...) -> None: ...

class XmlNamespace(_message.Message):
    __slots__ = ["prefix", "source", "uri"]
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    URI_FIELD_NUMBER: _ClassVar[int]
    prefix: str
    source: SourcePosition
    uri: str
    def __init__(self, prefix: _Optional[str] = ..., uri: _Optional[str] = ..., source: _Optional[_Union[SourcePosition, _Mapping]] = ...) -> None: ...

class XmlNode(_message.Message):
    __slots__ = ["element", "source", "text"]
    ELEMENT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    element: XmlElement
    source: SourcePosition
    text: str
    def __init__(self, element: _Optional[_Union[XmlElement, _Mapping]] = ..., text: _Optional[str] = ..., source: _Optional[_Union[SourcePosition, _Mapping]] = ...) -> None: ...
