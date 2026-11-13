#include "common/budget.hpp"
#ifndef TYPES_H
#define TYPES_H

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "raw/error.hpp"
#include "raw/opcodes.hpp"

namespace dexsplit::raw {

class DexFile;

namespace parser {
struct ParseOptions;
std::expected<DexFile, ParseError> parse_buffer(std::span<const uint8_t> buffer, ParseOptions options);
}  // namespace parser

struct Header {
  /** The magic value identifying the file as a DEX file. Usually dex\n035\0 or
   * similar. */
  std::uint8_t magic[8];
  /** An Adler-32 checksum of the rest of the file (excluding magic and this
   * field). */
  std::uint32_t checksum;
  /** A SHA-1 signature (hash) of the rest of the file (excluding magic,
   * checksum, and this field). */
  std::uint8_t signature[20];
  /** The total size of the entire file in bytes. (v41+: distance to next header
   * or end of container). */
  std::uint32_t file_size;
  /** The size of this header section in bytes. 0x70 (112 bytes) for v40 or
   * earlier. 0x78 (120 bytes) for v41 or later. */
  std::uint32_t header_size;
  /** Set to ENDIAN_CONSTANT (0x12345678) to indicate byte order. */
  std::uint32_t endian_tag;
  /** Size of the link section, or 0 if not statically linked. */
  std::uint32_t link_size;
  /** Offset from the start of the file to the link section. */
  std::uint32_t link_off;
  /** Offset from the start of the file to the map item. */
  std::uint32_t map_off;
  /** Count of string identifiers in the string identifiers list. */
  std::uint32_t string_ids_size;
  /** Offset from the start of the file to the string identifiers list. */
  std::uint32_t string_ids_off;
  /** Count of type identifiers in the type identifiers list (max 65535). */
  std::uint32_t type_ids_size;
  /** Offset from the start of the file to the type identifiers list. */
  std::uint32_t type_ids_off;
  /** Count of prototype identifiers in the prototype identifiers list (max
   * 65535). */
  std::uint32_t proto_ids_size;
  /** Offset from the start of the file to the prototype identifiers list. */
  std::uint32_t proto_ids_off;
  /** Count of field identifiers in the field identifiers list. */
  std::uint32_t field_ids_size;
  /** Offset from the start of the file to the field identifiers list. */
  std::uint32_t field_ids_off;
  /** Count of method identifiers in the method identifiers list. */
  std::uint32_t method_ids_size;
  /** Offset from the start of the file to the method identifiers list. */
  std::uint32_t method_ids_off;
  /** Count of class definitions in the class definitions list. */
  std::uint32_t class_defs_size;
  /** Offset from the start of the file to the class definitions list. */
  std::uint32_t class_defs_off;
  /** Size of the data section in bytes (v40-). Unused in v41+. */
  std::uint32_t data_size;
  /** Offset to the start of the data section (v40-). Unused in v41+. */
  std::uint32_t data_off;
  /** Size of the entire container (v41+). Assumed equal to file_size in v40-. */
  std::uint32_t container_size{0};
  /** Offset from the start of the file to the start of this header (v41+).
   * Assumed equal to 0 in v40-. */
  std::uint32_t header_offset{0};

  void print(std::ostream& os);
};

struct MapItem {
  /** Type of the items; see type codes. */
  std::uint16_t type;
  /** (unused) */
  std::uint16_t unused;
  /** Count of the number of items to be found at the indicated offset. */
  std::uint32_t size;
  /** Offset from the start of the file to the items in question. */
  std::uint32_t offset;
};

struct MapList {
  /** Size of the list, in entries. */
  std::uint32_t size;
  /** Elements of the list. */
  budget::Vector<MapItem> items;
};

struct ProtoIdItem {
  /** Index into the string_ids list for the short-form descriptor string of
   * this prototype. */
  uint32_t shorty_idx;
  /** Index into the type_ids list for the return type of this prototype. */
  uint32_t return_type_idx;
  /** Offset from the start of the file to the list of parameter types for this
   * prototype, or 0 if this prototype has no parameters. */
  uint32_t parameters_off;
};

struct FieldIdItem {
  /** Index into the type_ids list for the definer of this field. Must be a
   * class type. */
  uint16_t class_idx;
  /** Index into the type_ids list for the type of this field. */
  uint16_t type_idx;
  /** Index into the string_ids list for the name of this field. */
  uint32_t name_idx;
};

struct MethodIdItem {
  /** Index into the type_ids list for the definer of this method. Must be a
   * class or array type. */
  uint16_t class_idx;
  /** Index into the proto_ids list for the prototype of this method. */
  uint16_t proto_idx;
  /** Index into the string_ids list for the name of this method. */
  uint32_t name_idx;
};

struct ClassDefItem {
  /** Index into the type_ids list for this class. Must be a class type. */
  uint32_t class_idx;
  /** Access flags for the class (e.g., public, final). */
  uint32_t access_flags;
  /** Index into the type_ids list for the superclass, or NO_INDEX if this class
   * has no superclass. */
  uint32_t superclass_idx;
  /** Offset from the start of the file to the list of interfaces, or 0 if there
   * are none. */
  uint32_t interfaces_off;
  /** Index into the string_ids list for the name of the source file, or
   * NO_INDEX. */
  uint32_t source_file_idx;
  /** Offset from the start of the file to the annotations structure for this
   * class, or 0 if none. */
  uint32_t annotations_off;
  /** Offset from the start of the file to the associated class data, or 0 if
   * there is no class data. */
  uint32_t class_data_off;
  /** Offset from the start of the file to the list of initial values for static
   * fields, or 0 if none. */
  uint32_t static_values_off;
};

struct CallSiteIdItem {
  /** Offset from the start of the file to the call site definition. */
  uint32_t call_site_off;
};

struct MethodHandleItem {
  /** Type of the method handle (see method handle type codes). */
  uint16_t method_handle_type;
  /** (unused) */
  uint16_t unused1;
  /** Field or method ID depending on whether the method handle type is an
   * accessor or method invoker. */
  uint16_t field_or_method_id;
  /** (unused) */
  uint16_t unused2;
};

struct TypeList {
  /** Number of entries in the list. */
  uint32_t size;
  /** type_idx values (indices into type_ids). */
  budget::Vector<uint16_t> type_ids;
};

struct EncodedField {
  /** Absolute field index (decoded from ULEB128 delta). */
  uint32_t field_idx;
  /** Access flags for the field. */
  uint32_t access_flags;
};

struct EncodedMethod {
  /** Absolute method index (decoded from ULEB128 delta). */
  uint32_t method_idx;
  /** Access flags for the method. */
  uint32_t access_flags;
  /** Offset to code item, or 0 if abstract/native. */
  uint32_t code_off;
};

struct ClassDataItem {
  budget::Vector<EncodedField> static_fields;
  budget::Vector<EncodedField> instance_fields;
  budget::Vector<EncodedMethod> direct_methods;
  budget::Vector<EncodedMethod> virtual_methods;
};

struct TryItem {
  /** Start address of the try block (in 16-bit code units). */
  uint32_t start_addr;
  /** Number of 16-bit code units covered. */
  uint16_t insn_count;
  /** Byte offset from the start of the associated handler list to the handler. */
  uint16_t handler_off;
};

struct EncodedTypePair {
  /** Type index for the caught exception type. */
  uint32_t type_idx;
  /** Handler address (in 16-bit code units). */
  uint32_t addr;
};

struct EncodedCatchHandler {
  /** Explicitly-typed exception handlers. */
  budget::Vector<EncodedTypePair> handlers;
  /** Catch-all handler address; present when the encoded size is <= 0. */
  std::optional<uint32_t> catch_all_addr;
};

/// Validated instruction metadata reused by model conversion instead of decoding the body again.
struct CodeStructure {
  budget::Vector<uint32_t> starts;
  budget::Map<uint32_t, uint32_t> payloads;
  budget::Vector<uint32_t> targets;
};

struct CodeItem {
  /** Number of virtual registers used by this code. */
  uint16_t registers_size;
  /** Number of words of incoming arguments. */
  uint16_t ins_size;
  /** Number of words of outgoing argument space. */
  uint16_t outs_size;
  /** Number of try_items in this instance. */
  uint16_t tries_size;
  /** Offset to debug info, or 0 if none. */
  uint32_t debug_info_off;
  /** Size of the instructions list in 16-bit code units. */
  uint32_t insns_size;
  /** Raw bytecode (16-bit code units). */
  budget::Vector<uint16_t> insns;
  /** Try blocks; empty if tries_size == 0. */
  budget::Vector<TryItem> tries;
  /** Exception handlers; one per unique handler list. */
  budget::Vector<EncodedCatchHandler> handlers;
  /** Byte offset (within the encoded_catch_handler_list, measured from the
   *  start of the list — i.e. the list_size ULEB128) at which each handlers[k]
   *  was decoded.  Use to map a TryItem::handler_off to its handlers index. */
  budget::Vector<uint16_t> handler_byte_offsets;
  uint32_t end_offset = 0;
  uint32_t remaining_uses = 0;
  CodeStructure structure;
};

/** The "no index" value of 32-bit index fields (e.g. a class without a
 *  superclass) and of decoded uleb128p1 fields. */
inline constexpr uint32_t NO_INDEX = 0xFFFFFFFF;

/** Debug-info state machine opcodes (debug_info_item bytecode). */
enum DebugOpcode : uint8_t {
  DBG_END_SEQUENCE = 0x00,
  DBG_ADVANCE_PC = 0x01,
  DBG_ADVANCE_LINE = 0x02,
  DBG_START_LOCAL = 0x03,
  DBG_START_LOCAL_EXTENDED = 0x04,
  DBG_END_LOCAL = 0x05,
  DBG_RESTART_LOCAL = 0x06,
  DBG_SET_PROLOGUE_END = 0x07,
  DBG_SET_EPILOGUE_BEGIN = 0x08,
  DBG_SET_FILE = 0x09,
  DBG_FIRST_SPECIAL = 0x0a,  ///< Opcodes 0x0a..0xff each emit one position entry.
};

/** One opcode of a debug_info_item's state machine with its operands.  Index
 *  operands are uleb128p1 in the file; NO_INDEX here means "no index". */
struct DebugOp {
  /** A DebugOpcode, or a special opcode (>= DBG_FIRST_SPECIAL) that advances
   *  the address and line and emits a position entry. */
  uint8_t opcode;
  uint32_t addr_diff = 0;        ///< DBG_ADVANCE_PC
  int32_t line_diff = 0;         ///< DBG_ADVANCE_LINE
  uint32_t reg = 0;              ///< DBG_START_LOCAL(_EXTENDED), DBG_END_LOCAL, DBG_RESTART_LOCAL
  uint32_t name_idx = NO_INDEX;  ///< DBG_START_LOCAL(_EXTENDED): local name; DBG_SET_FILE: file
  uint32_t type_idx = NO_INDEX;  ///< DBG_START_LOCAL(_EXTENDED)
  uint32_t sig_idx = NO_INDEX;   ///< DBG_START_LOCAL_EXTENDED
};

struct DebugInfoItem {
  /** Initial value of the state machine's line register. */
  uint32_t line_start;
  /** One string index per entry of the parameter-name list (NO_INDEX = no
   *  name), as many as the item declares. */
  budget::Vector<uint32_t> parameter_names;
  /** The state machine's bytecode, in order, without DBG_END_SEQUENCE. */
  budget::Vector<DebugOp> ops;
};

struct FieldAnnotation {
  uint32_t field_idx;
  uint32_t annotations_off;
};

struct MethodAnnotation {
  uint32_t method_idx;
  uint32_t annotations_off;
};

struct ParameterAnnotation {
  uint32_t method_idx;
  uint32_t annotations_off;
};

struct AnnotationsDirectoryItem {
  /** Offset to annotations for the class itself, or 0. */
  uint32_t class_annotations_off;
  budget::Vector<FieldAnnotation> field_annotations;
  budget::Vector<MethodAnnotation> method_annotations;
  budget::Vector<ParameterAnnotation> parameter_annotations;
};

struct AnnotationSetItem {
  /** annotation_off values (offsets to annotation_item entries). */
  budget::Vector<uint32_t> entries;
};

struct AnnotationSetRefList {
  /** annotation_set_off values (offsets to annotation_set_item entries). */
  budget::Vector<uint32_t> entries;
};

struct EncodedAnnotation;

/** One decoded encoded_value.  `type` is the exact DEX value_type byte; the
 *  active variant alternative follows from it:
 *    Byte/Short/Int/Long  -> int64_t (sign-extended)
 *    Char                 -> int64_t (zero-extended)
 *    Boolean              -> bool
 *    Float/Double         -> double
 *    MethodType/MethodHandle/String/Type/Field/Method/Enum -> uint32_t pool index
 *    Array                -> budget::Vector<EncodedValue>
 *    Annotation           -> std::shared_ptr<EncodedAnnotation> (boxed; recursive)
 *    Null                 -> std::monostate
 *  Move-only because of the boxed annotation alternative. */
struct EncodedValue {
  enum class Type : uint8_t {
    Byte = 0x00,
    Short = 0x02,
    Char = 0x03,
    Int = 0x04,
    Long = 0x06,
    Float = 0x10,
    Double = 0x11,
    MethodType = 0x15,
    MethodHandle = 0x16,
    String = 0x17,
    Type = 0x18,
    Field = 0x19,
    Method = 0x1a,
    Enum = 0x1b,
    Array = 0x1c,
    Annotation = 0x1d,
    Null = 0x1e,
    Boolean = 0x1f,
  };

  Type type;
  std::variant<std::monostate, bool, int64_t, double, uint32_t, budget::Vector<EncodedValue>,
               std::shared_ptr<EncodedAnnotation>>
      value;
};

/** One name = value pair inside an encoded_annotation. */
struct AnnotationElement {
  /** Index into string_ids for the element name. */
  uint32_t name_idx;
  EncodedValue value;
};

/** The payload of an annotation: its type plus its explicitly-set elements.
 *  Elements left at their @interface defaults are NOT present here — defaults
 *  live in the dalvik.annotation.AnnotationDefault system annotation on the
 *  annotation class itself. */
struct EncodedAnnotation {
  /** Index into type_ids for the annotation class. */
  uint32_t type_idx;
  /** Elements in name_idx-ascending order, as required by the format. */
  budget::Vector<AnnotationElement> elements;
};

struct AnnotationItem {
  /** Visibility of the annotation: VISIBILITY_BUILD (0x00),
   *  VISIBILITY_RUNTIME (0x01), or VISIBILITY_SYSTEM (0x02). */
  uint8_t visibility;
  EncodedAnnotation annotation;
};

/**
 * DEX file representation — raw parsed data
 */
class DexFile {
  friend std::expected<DexFile, ParseError> parser::parse_buffer(std::span<const uint8_t> buffer,
                                                                 parser::ParseOptions options);
  DexFile() = default;

  Header header_;
  MapList map_list_;
  budget::Vector<uint32_t> string_ids_;
  budget::Vector<uint32_t> type_ids_;
  budget::Vector<ProtoIdItem> proto_ids_;
  budget::Vector<FieldIdItem> field_ids_;
  budget::Vector<MethodIdItem> method_ids_;
  budget::Vector<ClassDefItem> class_defs_;
  budget::Vector<CallSiteIdItem> call_site_ids_;
  budget::Vector<MethodHandleItem> method_handles_;
  budget::Vector<budget::String> strings_;
  budget::Map<uint32_t, CodeItem> code_items_;
  budget::Map<uint32_t, uint32_t> instruction_sizes_;

 public:
  /// Immutable, completely validated mapped code; all owners of a shared item reuse this instance.
  const CodeItem* code_item(uint32_t offset) const {
    auto found = code_items_.find(offset);
    return found == code_items_.end() ? nullptr : &found->second;
  }
  /// Conversion releases a parsed body only after its last mapped owner has consumed it.
  void release_code_item(uint32_t offset) {
    auto found = code_items_.find(offset);
    if (found != code_items_.end() && found->second.remaining_uses != 0 && --found->second.remaining_uses == 0) {
      code_items_.erase(found);
    }
  }
  /// Analysis owns the immutable input bytes and only needs validated instruction extents.
  void compact_for_analysis() {
    budget::Scope scope(code_items_.get_allocator().owner());
    for (const auto& [offset, item] : code_items_) {
      budget::visit();
      instruction_sizes_.emplace(offset, item.insns_size);
    }
    code_items_.clear();
  }
  uint32_t instruction_units(uint32_t offset) const {
    auto found = instruction_sizes_.find(offset);
    return found == instruction_sizes_.end() ? 0 : found->second;
  }
  const Header& header() const { return header_; }
  const MapList& map_list() const { return map_list_; }
  std::span<const uint32_t> string_ids() const { return string_ids_; }
  std::span<const uint32_t> type_ids() const { return type_ids_; }
  std::span<const ProtoIdItem> proto_ids() const { return proto_ids_; }
  std::span<const FieldIdItem> field_ids() const { return field_ids_; }
  std::span<const MethodIdItem> method_ids() const { return method_ids_; }
  std::span<const ClassDefItem> class_defs() const { return class_defs_; }
  std::span<const CallSiteIdItem> call_site_ids() const { return call_site_ids_; }
  std::span<const MethodHandleItem> method_handles() const { return method_handles_; }
  std::span<const budget::String> strings() const { return strings_; }
};

}  // namespace dexsplit::raw

#endif  // TYPES_H
