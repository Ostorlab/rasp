#include "raw/validate.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <tuple>

#include "common/budget.hpp"
#include "raw/constants.hpp"
#include "raw/descriptors.hpp"
#include "raw/mutf8.hpp"
#include "raw/opcodes.hpp"
#include "raw/parser.hpp"
#include "raw/parsing_utils.hpp"

namespace dexsplit::raw {
namespace {
struct Failure : std::exception {
  ParseError error;
  explicit Failure(ParseError value) : error(std::move(value)) {}
  const char* what() const noexcept override { return error.message.c_str(); }
};
class Layout {
 public:
  explicit Layout(std::span<const uint8_t> bytes) : bytes_(bytes), region_(bytes) {}
  template <class T>
  T check(std::expected<T, ParseError> result) {
    if (!result) {
      throw Failure{result.error()};
    }
    return std::move(*result);
  }
  [[noreturn]] void fail(const char* message) { throw Failure{{ParseError::Code::MalformedData, message, cursor_}}; }
  uint32_t u32() { return check(parse_utils::read_uint32(region_, cursor_)); }
  uint32_t u16() { return check(parse_utils::read_uint16(region_, cursor_)); }
  uint32_t leb() { return check(parse_utils::read_uleb128(region_, cursor_)); }
  int32_t sleb() { return check(parse_utils::read_sleb128(region_, cursor_)); }
  void skip(uint64_t count) {
    if (cursor_ > region_.size() || count > region_.size() - cursor_) {
      fail("item extends outside its mapped section");
    }
    budget::visit(static_cast<std::size_t>(count / 64 + 1));
    cursor_ += static_cast<uint32_t>(count);
  }
  void reference(uint32_t offset, uint16_t type, bool optional = true) {
    if (offset == 0 && optional) {
      return;
    }
    references_.emplace_back(offset, type);
  }
  uint32_t alignment(uint16_t type) {
    return type == TYPE_CLASS_DATA_ITEM || (type >= TYPE_STRING_DATA_ITEM && type <= TYPE_ENCODED_ARRAY_ITEM) ? 1 : 4;
  }
  uint8_t type_prefix(uint32_t index) {
    if (index >= header_.type_ids_size) {
      fail("code type index out of range");
    }
    uint32_t at = header_.type_ids_off + index * 4;
    const auto string_index = check(parse_utils::read_uint32(bytes_, at));
    if (string_index >= header_.string_ids_size) {
      fail("code type string index out of range");
    }
    at = header_.string_ids_off + string_index * 4;
    auto position = check(parse_utils::read_uint32(bytes_, at));
    check(parse_utils::read_uleb128(bytes_, position));
    if (position >= bytes_.size()) {
      fail("code type descriptor outside input");
    }
    return bytes_[position];
  }
  static bool field_prefix(uint8_t prefix) {
    return std::string_view("BCDFIJSZL[").find(static_cast<char>(prefix)) != std::string_view::npos;
  }
  void code() {
    const auto start = cursor_;
    auto item = check(parser::parse_code_item(region_, cursor_));
    reference(item.debug_info_off, TYPE_DEBUG_INFO_ITEM);
    for (const auto at : item.structure.starts) {
      budget::visit();
      const auto decoded = check(decode_insn(item.insns, at));
      const auto& info = opcode_info(decoded.opcode);
      if ((decoded.opcode >= 0xfa && version_ < 38) || (decoded.opcode >= 0xfe && version_ < 39)) {
        fail("mapped opcode requires later DEX version");
      }
      const std::array<uint32_t, 8> limits{0,
                                           header_.string_ids_size,
                                           header_.type_ids_size,
                                           header_.field_ids_size,
                                           header_.method_ids_size,
                                           header_.proto_ids_size,
                                           call_sites_,
                                           handles_};
      if (info.ref != RefKind::None && decoded.index >= limits[static_cast<std::size_t>(info.ref)]) {
        fail("mapped instruction pool index out of range");
      }
      if ((decoded.opcode == 0xfa || decoded.opcode == 0xfb) && decoded.proto >= header_.proto_ids_size) {
        fail("mapped instruction prototype index out of range");
      }
      if (info.ref == RefKind::Type) {
        const auto prefix = type_prefix(decoded.index);
        if (!field_prefix(prefix) || (decoded.opcode == 0x22 && prefix != 'L') ||
            (decoded.opcode >= 0x23 && decoded.opcode <= 0x25 && prefix != '[')) {
          fail("mapped instruction requires a different type kind");
        }
      }
    }
    for (const auto& handler : item.handlers) {
      budget::visit();
      for (const auto& caught : handler.handlers) {
        budget::visit();
        if (caught.type_idx >= header_.type_ids_size || type_prefix(caught.type_idx) != 'L') {
          fail("mapped catch type must name a class");
        }
      }
    }
    cursor_ = item.end_offset;
    code_items_.emplace(start, std::move(item));
  }
  void debug_index(uint32_t limit) {
    if (leb() > limit) {
      fail("debug pool index out of range");
    }
  }
  void debug() {
    DebugSummary summary{cursor_, 0, 0, 0};
    int64_t line = leb();
    uint64_t address = 0;
    uint32_t count = leb();
    summary.parameters = count;
    for (uint32_t i = 0; i < count; ++i) {
      budget::visit();
      debug_index(header_.string_ids_size);
    }
    auto local = [&] {
      const auto reg = leb();
      summary.registers = std::max(summary.registers, std::min(reg, 65535U) + 1);
    };
    while (true) {
      budget::visit();
      if (cursor_ >= region_.size()) {
        fail("unterminated debug information");
      }
      uint8_t opcode = region_[cursor_++];
      if (opcode == 1) {
        address += leb();
      } else if (opcode == 5 || opcode == 6) {
        local();
      } else if (opcode == 9) {
        debug_index(header_.string_ids_size);
      } else if (opcode == 2) {
        line += sleb();
      } else if (opcode == 3 || opcode == 4) {
        local();
        debug_index(header_.string_ids_size);
        const auto type = leb();
        if (type > header_.type_ids_size || (type != 0 && !field_prefix(type_prefix(type - 1)))) {
          fail("debug local type is not a field type");
        }
        if (opcode == 4) {
          debug_index(header_.string_ids_size);
        }
      } else if (opcode >= 10) {
        const auto adjusted = static_cast<uint32_t>(opcode - 10);
        address += adjusted / 15;
        line += -4 + static_cast<int64_t>(adjusted % 15);
      }
      // Match emitted and terminal bounds; advance operations may have legal transient line states.
      if (opcode != 1 && opcode != 2) {
        if (line < 0 || line > UINT32_MAX) {
          fail("debug line outside supported range");
        }
        summary.address = std::max(summary.address, static_cast<uint32_t>(std::min<uint64_t>(address, UINT32_MAX)));
      }
      if (opcode == 0) {
        debug_summaries_.push_back(summary);
        return;
      }
    }
  }
  void class_data() {
    std::array<uint32_t, 4> counts{};
    for (auto& count : counts) {
      dexsplit::budget::visit();
      count = leb();
    }
    for (std::size_t group = 0; group < counts.size(); ++group) {
      dexsplit::budget::visit();
      uint32_t previous = 0;
      for (uint32_t i = 0; i < counts[group]; ++i) {
        dexsplit::budget::visit();
        uint32_t delta = leb();
        if ((i != 0 && delta == 0) || delta > UINT32_MAX - previous) {
          fail("class member index delta overflow/duplicate");
        }
        previous += delta;
        if (previous >= (group < 2 ? header_.field_ids_size : header_.method_ids_size)) {
          fail("class member index out of range");
        }
        leb();
        if (group >= 2) {
          reference(leb(), TYPE_CODE_ITEM);
        }
      }
    }
  }
  const budget::String& string(uint32_t index) {
    if (index >= header_.string_ids_size) {
      fail("encoded value string index out of range");
    }
    auto found = strings_.find(index);
    if (found != strings_.end()) {
      return found->second;
    }
    uint32_t at = header_.string_ids_off + index * 4;
    uint32_t offset = check(parse_utils::read_uint32(bytes_, at));
    return strings_.emplace(index, check(mutf8::decode_string_data(bytes_, offset))).first->second;
  }
  budget::String type_name(uint32_t index) {
    if (index >= header_.type_ids_size) {
      fail("annotation type index out of range");
    }
    uint32_t at = header_.type_ids_off + index * 4;
    return string(check(parse_utils::read_uint32(bytes_, at)));
  }
  void annotation(const EncodedAnnotation& value) {
    budget::visit();
    if (!is_valid_class_descriptor(type_name(value.type_idx), version_)) {
      fail("invalid annotation class descriptor");
    }
    uint32_t previous = 0;
    for (std::size_t i = 0; i < value.elements.size(); ++i) {
      const auto& element = value.elements[i];
      if ((i != 0 && element.name_idx <= previous) || !is_valid_simple_name(string(element.name_idx), version_)) {
        fail("invalid/unsorted annotation elements");
      }
      previous = element.name_idx;
      encoded_value(element.value);
    }
  }
  void encoded_value(const EncodedValue& value) {
    budget::visit();
    uint32_t limit = 0;
    switch (value.type) {
      case EncodedValue::Type::String:
        limit = header_.string_ids_size;
        break;
      case EncodedValue::Type::Type:
        limit = header_.type_ids_size;
        break;
      case EncodedValue::Type::Field:
      case EncodedValue::Type::Enum:
        limit = header_.field_ids_size;
        break;
      case EncodedValue::Type::Method:
        limit = header_.method_ids_size;
        break;
      case EncodedValue::Type::MethodType:
        if (version_ < 38) {
          fail("method type requires DEX 038");
        }
        limit = header_.proto_ids_size;
        break;
      case EncodedValue::Type::MethodHandle:
        if (version_ < 38) {
          fail("method handle requires DEX 038");
        }
        limit = handles_;
        break;
      case EncodedValue::Type::Array:
        for (const auto& child : std::get<budget::Vector<EncodedValue>>(value.value)) {
          encoded_value(child);
        }
        return;
      case EncodedValue::Type::Annotation:
        annotation(*std::get<std::shared_ptr<EncodedAnnotation>>(value.value));
        return;
      default:
        return;
    }
    if (std::get<uint32_t>(value.value) >= limit) {
      fail("encoded value pool index out of range");
    }
  }
  void item(uint16_t type) {
    switch (type) {
      case TYPE_HEADER_ITEM:
        skip(112);
        break;
      case TYPE_STRING_ID_ITEM:
        reference(u32(), TYPE_STRING_DATA_ITEM, false);
        break;
      case TYPE_TYPE_ID_ITEM:
        skip(4);
        break;
      case TYPE_PROTO_ID_ITEM:
        skip(8);
        reference(u32(), TYPE_TYPE_LIST);
        break;
      case TYPE_FIELD_ID_ITEM:
      case TYPE_METHOD_ID_ITEM:
      case TYPE_METHOD_HANDLE_ITEM:
        skip(8);
        break;
      case TYPE_CLASS_DEF_ITEM:
        skip(12);
        reference(u32(), TYPE_TYPE_LIST);
        skip(4);
        reference(u32(), TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        reference(u32(), TYPE_CLASS_DATA_ITEM);
        reference(u32(), TYPE_ENCODED_ARRAY_ITEM);
        break;
      case TYPE_CALL_SITE_ID_ITEM:
        reference(u32(), TYPE_ENCODED_ARRAY_ITEM, false);
        break;
      case TYPE_MAP_LIST: {
        uint32_t count = u32();
        skip(uint64_t{count} * 12);
        break;
      }
      case TYPE_TYPE_LIST: {
        uint32_t count = u32();
        for (uint32_t i = 0; i < count; ++i) {
          budget::visit();
          if (u16() >= header_.type_ids_size) {
            fail("type-list index out of range");
          }
        }
        break;
      }
      case TYPE_ANNOTATION_SET_REF_LIST:
      case TYPE_ANNOTATION_SET_ITEM: {
        uint32_t count = u32();
        uint32_t previous = 0;
        for (uint32_t i = 0; i < count; ++i) {
          budget::visit();
          uint32_t offset = u32();
          reference(offset, type == TYPE_ANNOTATION_SET_ITEM ? TYPE_ANNOTATION_ITEM : TYPE_ANNOTATION_SET_ITEM,
                    type == TYPE_ANNOTATION_SET_REF_LIST);
          if (type == TYPE_ANNOTATION_SET_ITEM) {
            if (offset >= bytes_.size()) {
              fail("annotation offset out of range");
            }
            uint32_t at = offset + 1;
            uint32_t annotation_type = check(parse_utils::read_uleb128(bytes_, at));
            if (annotation_type >= header_.type_ids_size || (i != 0 && annotation_type <= previous)) {
              fail("annotation set types are not sorted/unique");
            }
            previous = annotation_type;
          }
        }
        break;
      }
      case TYPE_CLASS_DATA_ITEM:
        class_data();
        break;
      case TYPE_CODE_ITEM:
        code();
        break;
      case TYPE_STRING_DATA_ITEM: {
        check(mutf8::decode_string_data(region_, cursor_));
        leb();
        auto terminator = std::find(region_.begin() + cursor_, region_.end(), 0);
        if (terminator == region_.end()) {
          fail("unterminated DEX string");
        }
        skip(static_cast<uint64_t>(terminator - (region_.begin() + cursor_)) + 1);
        break;
      }
      case TYPE_DEBUG_INFO_ITEM:
        debug();
        break;
      case TYPE_ANNOTATION_ITEM: {
        if (cursor_ >= region_.size() || region_[cursor_] > 2) {
          fail("invalid annotation visibility");
        }
        ++cursor_;
        annotation(check(parser::parse_encoded_annotation(region_, cursor_)));
        break;
      }
      case TYPE_ENCODED_ARRAY_ITEM:
        for (const auto& value : check(parser::parse_encoded_array(region_, cursor_))) {
          encoded_value(value);
        }
        break;
      case TYPE_ANNOTATIONS_DIRECTORY_ITEM: {
        reference(u32(), TYPE_ANNOTATION_SET_ITEM);
        std::array<uint32_t, 3> counts{};
        for (auto& count : counts) {
          dexsplit::budget::visit();
          count = u32();
        }
        for (std::size_t group = 0; group < counts.size(); ++group) {
          dexsplit::budget::visit();
          uint32_t previous = 0;
          for (uint32_t i = 0; i < counts[group]; ++i) {
            dexsplit::budget::visit();
            uint32_t index = u32();
            if (index >= (group == 0 ? header_.field_ids_size : header_.method_ids_size)) {
              fail("annotation directory member index out of range");
            }
            if (i != 0 && index <= previous) {
              fail("unsorted annotation directory");
            }
            previous = index;
            reference(u32(), group == 2 ? TYPE_ANNOTATION_SET_REF_LIST : TYPE_ANNOTATION_SET_ITEM, false);
          }
        }
        break;
      }
      default:
        fail("unsupported mapped DEX section");
    }
  }
  void run() {
    if (bytes_.size() > budget::kDexBytes) {
      fail("DEX exceeds 64 MiB compatibility limit");
    }
    Header header = check(parser::parse_header(bytes_));
    header_ = header;
    uint32_t version = (header.magic[4] - '0') * 100U + (header.magic[5] - '0') * 10U + header.magic[6] - '0';
    version_ = version;
    if (version != 35 && version != 37 && version != 38 && version != 39 && version != 40) {
      fail("unsupported DEX version");
    }
    if (header.file_size != bytes_.size() || header.header_size != 112 || header.endian_tag != ENDIAN_CONSTANT) {
      fail("inconsistent DEX file/header size or endian tag");
    }
    if (header.link_size != 0 || header.link_off != 0) {
      fail("unsupported DEX link section");
    }
    if (header.data_off < 112 || header.data_off % 4 != 0 || header.data_off > bytes_.size() ||
        header.data_size != bytes_.size() - header.data_off) {
      fail("inconsistent DEX data size/offset");
    }
    if (header.checksum != check(parser::compute_checksum(bytes_))) {
      fail("DEX checksum mismatch");
    }
    auto signature = check(parser::compute_signature(bytes_));
    if (std::memcmp(header.signature, signature.data(), signature.size()) != 0) {
      fail("DEX signature mismatch");
    }
    if (header.map_off < header.data_off || header.map_off % 4 != 0) {
      fail("invalid DEX map offset");
    }
    auto map = check(parser::parse_map_list(bytes_, header.map_off));
    for (const auto& section : map.items) {
      if ((section.type == TYPE_METHOD_HANDLE_ITEM || section.type == TYPE_CALL_SITE_ID_ITEM) && version_ < 38) {
        fail("mapped method handles/call sites require DEX 038");
      }
      if (section.type == TYPE_METHOD_HANDLE_ITEM) {
        handles_ = section.size;
      }
      if (section.type == TYPE_CALL_SITE_ID_ITEM) {
        call_sites_ = section.size;
      }
    }
    if (map.items.empty() || map.items.size() > 32) {
      fail("invalid DEX map count");
    }
    std::array<std::pair<uint32_t, uint32_t>, 7> fixed{{{1, 0},
                                                        {header.string_ids_size, header.string_ids_off},
                                                        {header.type_ids_size, header.type_ids_off},
                                                        {header.proto_ids_size, header.proto_ids_off},
                                                        {header.field_ids_size, header.field_ids_off},
                                                        {header.method_ids_size, header.method_ids_off},
                                                        {header.class_defs_size, header.class_defs_off}}};
    budget::Set<uint16_t> types;
    uint32_t previous = 0;
    for (std::size_t i = 0; i < map.items.size(); ++i) {
      dexsplit::budget::visit();
      const auto& section = map.items[i];
      if (section.unused != 0 || section.size == 0 || !types.insert(section.type).second ||
          (i != 0 && section.offset <= previous)) {
        fail("duplicate/unsorted/empty DEX map section");
      }
      previous = section.offset;
      uint32_t end = i + 1 < map.items.size() ? map.items[i + 1].offset : static_cast<uint32_t>(bytes_.size());
      if (section.offset >= end || end > bytes_.size() || section.offset % alignment(section.type) != 0) {
        fail("invalid mapped DEX range/alignment");
      }
      if (section.type <= TYPE_CLASS_DEF_ITEM && fixed[section.type] != std::pair{section.size, section.offset}) {
        fail("DEX header/map table disagreement");
      }
      if (section.type > TYPE_CLASS_DEF_ITEM && section.offset < header.data_off &&
          section.type != TYPE_CALL_SITE_ID_ITEM && section.type != TYPE_METHOD_HANDLE_ITEM) {
        fail("data item outside DEX data section");
      }
      if (section.type == TYPE_MAP_LIST && (section.offset != header.map_off || section.size != 1)) {
        fail("DEX map self-reference mismatch");
      }
      if ((section.type == TYPE_STRING_ID_ITEM && section.size > budget::kStrings) ||
          (section.type == TYPE_CLASS_DEF_ITEM && section.size > budget::kClasses)) {
        fail("DEX class/string compatibility limit exceeded");
      }
      if ((section.type == TYPE_TYPE_ID_ITEM || section.type == TYPE_PROTO_ID_ITEM) && section.size > 65535) {
        fail("DEX type/prototype pool limit exceeded");
      }
      if ((section.type == TYPE_FIELD_ID_ITEM || section.type == TYPE_METHOD_ID_ITEM ||
           section.type == TYPE_CALL_SITE_ID_ITEM || section.type == TYPE_METHOD_HANDLE_ITEM) &&
          section.size > 65536) {
        fail("DEX member pool limit exceeded");
      }
      if (section.type == TYPE_DEBUG_INFO_ITEM) {
        if (section.size > (end - section.offset) / 3) {
          fail("mapped debug item count exceeds its section");
        }
        debug_summaries_.reserve(section.size);
      }
      region_ = bytes_.first(end);
      cursor_ = section.offset;
      for (uint32_t n = 0; n < section.size; ++n) {
        dexsplit::budget::visit();
        while (cursor_ % alignment(section.type) != 0) {
          dexsplit::budget::visit();
          if (cursor_ >= region_.size() || region_[cursor_] != 0) {
            fail("invalid item padding");
          }
          skip(1);
        }
        if (cursor_ >= region_.size() || !items_.emplace(cursor_, section.type).second) {
          fail("invalid/overlapping DEX item");
        }
        item(section.type);
      }
      if (cursor_ > end) {
        fail(budget::format("mapped DEX section 0x{:04x} ends at {}, next section {}", section.type, cursor_, end)
                 .c_str());
      }
      while (cursor_ < end) {
        dexsplit::budget::visit();
        if (region_[cursor_] != 0) {
          fail("nonzero DEX padding");
        }
        skip(1);
      }
    }
    for (std::size_t type = 0; type < fixed.size(); ++type) {
      dexsplit::budget::visit();
      if ((fixed[type].first != 0) != types.contains(static_cast<uint16_t>(type)) ||
          (fixed[type].first == 0 && fixed[type].second != 0)) {
        fail("missing/inconsistent fixed DEX section");
      }
    }
    if (!types.contains(TYPE_MAP_LIST)) {
      fail("missing DEX map section");
    }
    for (const auto& [offset, type] : references_) {
      dexsplit::budget::visit();
      auto found = items_.find(offset);
      if (found == items_.end() || found->second != type) {
        fail("DEX reference is not a typed item boundary");
      }
      if (type == TYPE_CODE_ITEM) {
        ++code_items_.at(offset).remaining_uses;
      }
    }
    // Summaries are emitted in physical offset order, regardless of where code sections occur.
    for (const auto& [offset, code] : code_items_) {
      budget::visit();
      if (code.debug_info_off == 0) {
        continue;
      }
      const auto found = std::lower_bound(
          debug_summaries_.begin(), debug_summaries_.end(), code.debug_info_off,
          [](const DebugSummary& summary, uint32_t debug_offset) { return summary.offset < debug_offset; });
      if (found == debug_summaries_.end() || found->offset != code.debug_info_off ||
          found->registers > code.registers_size || found->address > code.insns_size ||
          found->parameters > code.ins_size) {
        fail("debug register/position/parameter bounds exceed mapped code frame");
      }
    }
  }

  budget::Map<uint32_t, CodeItem> take_code_items() { return std::move(code_items_); }

 private:
  struct DebugSummary {
    uint32_t offset;
    uint32_t address;
    uint32_t registers;
    uint32_t parameters;
  };
  budget::Vector<DebugSummary> debug_summaries_;
  budget::Map<uint32_t, CodeItem> code_items_;
  std::span<const uint8_t> bytes_, region_;
  Header header_{};
  uint32_t version_ = 0;
  uint32_t handles_ = 0;
  uint32_t call_sites_ = 0;
  budget::Map<uint32_t, budget::String> strings_;
  uint32_t cursor_ = 0;
  budget::Map<uint32_t, uint16_t> items_;
  budget::Vector<std::pair<uint32_t, uint16_t>> references_;
};
}  // namespace
std::expected<budget::Map<uint32_t, CodeItem>, ParseError> parse_layout(std::span<const uint8_t> bytes) {
  budget::Scope scope;
  try {
    Layout layout(bytes);
    layout.run();
    return layout.take_code_items();
  } catch (Failure& failure) {
    return std::unexpected(std::move(failure.error));
  }
}
std::expected<void, ParseError> validate_layout(std::span<const uint8_t> bytes) {
  auto result = parse_layout(bytes);
  if (!result) {
    return std::unexpected(result.error());
  }
  return {};
}
}  // namespace dexsplit::raw
