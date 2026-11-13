#include "raw/parser.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "common/budget.hpp"
#include "raw/code_validation.hpp"
#include "raw/constants.hpp"
#include "raw/digest.hpp"
#include "raw/parsing_utils.hpp"
#include "raw/validate.hpp"

// Error-propagation helpers for parse_utils calls.
// These macros assume `buf` and `offset` are in scope, and that the enclosing
// function returns std::expected<..., ParseError>.
#define TRY_U32(target)                              \
  do {                                               \
    auto _r = parse_utils::read_uint32(buf, offset); \
    if (!_r) return std::unexpected(_r.error());     \
    (target) = *_r;                                  \
  } while (0)

#define TRY_U16(target)                              \
  do {                                               \
    auto _r = parse_utils::read_uint16(buf, offset); \
    if (!_r) return std::unexpected(_r.error());     \
    (target) = *_r;                                  \
  } while (0)

#define TRY_ULEB128(target)                           \
  do {                                                \
    auto _r = parse_utils::read_uleb128(buf, offset); \
    if (!_r) return std::unexpected(_r.error());      \
    (target) = *_r;                                   \
  } while (0)

#define SKIP_ULEB128()                                \
  do {                                                \
    auto _r = parse_utils::read_uleb128(buf, offset); \
    if (!_r) return std::unexpected(_r.error());      \
  } while (0)

#define TRY_MUTF8(target)                             \
  do {                                                \
    auto _r = parse_utils::decode_mutf8(buf, offset); \
    if (!_r) return std::unexpected(_r.error());      \
    (target) = std::move(*_r);                        \
  } while (0)

namespace dexsplit::raw::parser {

namespace {

// Clamp an attacker-controlled element count to what the bytes remaining in the
// buffer could possibly hold before reserving.  A malformed count or ULEB128 —
// e.g. a 5-byte 0xFFFFFFFF catch-handler-list size, or a class_data claiming
// billions of methods — must not translate into a multi-gigabyte speculative
// allocation; the read loop still validates and bounds-checks every element, so
// this only caps the up-front reserve.  For valid input @p count never exceeds
// this bound, so legitimate reserves are unaffected.
template <class T>
void reserve_bounded(budget::Vector<T>& v, uint64_t count, std::span<const std::uint8_t> buf,
                     std::pair<uint32_t, uint64_t> extent) {
  auto [offset, min_elem_bytes] = extent;
  uint64_t remaining = offset <= buf.size() ? buf.size() - offset : 0;
  uint64_t cap = min_elem_bytes ? remaining / min_elem_bytes : 0;
  v.reserve(static_cast<std::size_t>(count < cap ? count : cap));
}

}  // namespace

std::expected<Header, ParseError> parse_header(std::span<const std::uint8_t> buf, std::uint32_t offset) {
  constexpr std::uint32_t MIN_HEADER_SIZE = 0x70;
  if (buf.size() < static_cast<std::size_t>(offset) + MIN_HEADER_SIZE) {
    return std::unexpected(
        ParseError::truncated_file(offset + MIN_HEADER_SIZE, static_cast<std::uint32_t>(buf.size())));
  }

  Header header{};

  // magic (8 bytes)
  std::memcpy(header.magic, buf.data() + offset, 8);
  offset += 8;

  // Check magic: "dex\n" followed by 3 version digits and null terminator
  if (header.magic[0] != 0x64 || header.magic[1] != 0x65 || header.magic[2] != 0x78 || header.magic[3] != 0x0a ||
      header.magic[7] != 0x00 || header.magic[4] < 0x30 || header.magic[4] > 0x39 || header.magic[5] < 0x30 ||
      header.magic[5] > 0x39 || header.magic[6] < 0x30 || header.magic[6] > 0x39) {
    return std::unexpected(ParseError::invalid_magic(0));
  }

  TRY_U32(header.checksum);

  std::memcpy(header.signature, buf.data() + offset, 20);
  offset += 20;

  TRY_U32(header.file_size);
  TRY_U32(header.header_size);
  TRY_U32(header.endian_tag);
  TRY_U32(header.link_size);
  TRY_U32(header.link_off);
  TRY_U32(header.map_off);
  TRY_U32(header.string_ids_size);
  TRY_U32(header.string_ids_off);
  TRY_U32(header.type_ids_size);
  TRY_U32(header.type_ids_off);
  TRY_U32(header.proto_ids_size);
  TRY_U32(header.proto_ids_off);
  TRY_U32(header.field_ids_size);
  TRY_U32(header.field_ids_off);
  TRY_U32(header.method_ids_size);
  TRY_U32(header.method_ids_off);
  TRY_U32(header.class_defs_size);
  TRY_U32(header.class_defs_off);
  TRY_U32(header.data_size);
  TRY_U32(header.data_off);

  // Handle v41+ header fields (120 bytes total)
  if (header.header_size >= 0x78) {
    if (buf.size() < static_cast<std::size_t>(offset) + 8) {
      return std::unexpected(ParseError::truncated_file(offset + 8, static_cast<std::uint32_t>(buf.size())));
    }
    TRY_U32(header.container_size);
    TRY_U32(header.header_offset);
  } else {
    header.container_size = header.file_size;
    header.header_offset = 0;
  }

  return header;
}

std::expected<MapList, ParseError> parse_map_list(std::span<const std::uint8_t> buf, uint32_t offset) {
  if (buf.size() < static_cast<std::size_t>(offset) + 4) {
    return std::unexpected(ParseError::truncated_file(offset + 4, static_cast<uint32_t>(buf.size())));
  }

  MapList map_list{};
  TRY_U32(map_list.size);

  constexpr uint32_t MAP_ITEM_SIZE = 12;
  uint64_t total_size = static_cast<uint64_t>(map_list.size) * MAP_ITEM_SIZE;
  if (buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  map_list.items.reserve(map_list.size);
  for (uint32_t i = 0; i < map_list.size; ++i) {
    dexsplit::budget::visit();
    MapItem item{};
    TRY_U16(item.type);
    TRY_U16(item.unused);
    TRY_U32(item.size);
    TRY_U32(item.offset);
    map_list.items.push_back(item);
  }

  return map_list;
}

std::expected<budget::Vector<uint32_t>, ParseError> parse_string_ids(std::span<const std::uint8_t> buf, uint32_t offset,
                                                                     uint32_t count) {
  constexpr uint32_t STRING_ID_SIZE = 4;
  uint64_t total_size = static_cast<uint64_t>(count) * STRING_ID_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<uint32_t> string_ids;
  string_ids.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    uint32_t val{};
    TRY_U32(val);
    string_ids.push_back(val);
  }

  return string_ids;
}

std::expected<std::pair<budget::String, uint32_t>, ParseError> parse_string(std::span<const std::uint8_t> buf,
                                                                            uint32_t offset) {
  if (offset >= buf.size()) {
    return std::unexpected(ParseError::truncated_file(1, static_cast<uint32_t>(buf.size())));
  }

  // skip the utf16_size ULEB128 prefix
  SKIP_ULEB128();

  budget::String str{};
  TRY_MUTF8(str);

  return std::make_pair(std::move(str), offset);
}

std::expected<budget::Vector<budget::String>, ParseError> parse_strings(std::span<const std::uint8_t> buf,
                                                                        const budget::Vector<uint32_t>& string_ids) {
  budget::Vector<budget::String> strings;
  strings.reserve(string_ids.size());

  for (uint32_t id_offset : string_ids) {
    dexsplit::budget::visit();
    auto result = parse_string(buf, id_offset);
    if (!result) {
      return std::unexpected(result.error());
    }
    strings.push_back(std::move(result->first));
  }

  return strings;
}

std::expected<budget::Vector<uint32_t>, ParseError> parse_type_ids(std::span<const std::uint8_t> buf, uint32_t offset,
                                                                   uint32_t count) {
  constexpr uint32_t TYPE_ID_SIZE = 4;
  uint64_t total_size = static_cast<uint64_t>(count) * TYPE_ID_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<uint32_t> type_ids;
  type_ids.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    uint32_t val{};
    TRY_U32(val);
    type_ids.push_back(val);
  }

  return type_ids;
}

std::expected<budget::Vector<ProtoIdItem>, ParseError> parse_proto_ids(std::span<const std::uint8_t> buf,
                                                                       uint32_t offset, uint32_t count) {
  constexpr uint32_t PROTO_ID_SIZE = 12;
  uint64_t total_size = static_cast<uint64_t>(count) * PROTO_ID_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<ProtoIdItem> proto_ids;
  proto_ids.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    ProtoIdItem item{};
    TRY_U32(item.shorty_idx);
    TRY_U32(item.return_type_idx);
    TRY_U32(item.parameters_off);
    proto_ids.push_back(item);
  }

  return proto_ids;
}

std::expected<budget::Vector<FieldIdItem>, ParseError> parse_field_ids(std::span<const std::uint8_t> buf,
                                                                       uint32_t offset, uint32_t count) {
  constexpr uint32_t FIELD_ID_SIZE = 8;
  uint64_t total_size = static_cast<uint64_t>(count) * FIELD_ID_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<FieldIdItem> field_ids;
  field_ids.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    FieldIdItem item{};
    TRY_U16(item.class_idx);
    TRY_U16(item.type_idx);
    TRY_U32(item.name_idx);
    field_ids.push_back(item);
  }

  return field_ids;
}

std::expected<budget::Vector<MethodIdItem>, ParseError> parse_method_ids(std::span<const std::uint8_t> buf,
                                                                         uint32_t offset, uint32_t count) {
  constexpr uint32_t METHOD_ID_SIZE = 8;
  uint64_t total_size = static_cast<uint64_t>(count) * METHOD_ID_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<MethodIdItem> method_ids;
  method_ids.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    MethodIdItem item{};
    TRY_U16(item.class_idx);
    TRY_U16(item.proto_idx);
    TRY_U32(item.name_idx);
    method_ids.push_back(item);
  }

  return method_ids;
}

std::expected<budget::Vector<ClassDefItem>, ParseError> parse_class_defs(std::span<const std::uint8_t> buf,
                                                                         uint32_t offset, uint32_t count) {
  constexpr uint32_t CLASS_DEF_SIZE = 32;
  uint64_t total_size = static_cast<uint64_t>(count) * CLASS_DEF_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<ClassDefItem> class_defs;
  class_defs.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    ClassDefItem item{};
    TRY_U32(item.class_idx);
    TRY_U32(item.access_flags);
    TRY_U32(item.superclass_idx);
    TRY_U32(item.interfaces_off);
    TRY_U32(item.source_file_idx);
    TRY_U32(item.annotations_off);
    TRY_U32(item.class_data_off);
    TRY_U32(item.static_values_off);
    class_defs.push_back(item);
  }

  return class_defs;
}

std::expected<budget::Vector<CallSiteIdItem>, ParseError> parse_call_site_ids(std::span<const std::uint8_t> buf,
                                                                              uint32_t offset, uint32_t count) {
  constexpr uint32_t CALL_SITE_ID_SIZE = 4;
  uint64_t total_size = static_cast<uint64_t>(count) * CALL_SITE_ID_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<CallSiteIdItem> call_site_ids;
  call_site_ids.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    CallSiteIdItem item{};
    TRY_U32(item.call_site_off);
    call_site_ids.push_back(item);
  }

  return call_site_ids;
}

std::expected<budget::Vector<MethodHandleItem>, ParseError> parse_method_handles(std::span<const std::uint8_t> buf,
                                                                                 uint32_t offset, uint32_t count) {
  constexpr uint32_t METHOD_HANDLE_SIZE = 8;
  uint64_t total_size = static_cast<uint64_t>(count) * METHOD_HANDLE_SIZE;

  if (count > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  budget::Vector<MethodHandleItem> method_handles;
  method_handles.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    dexsplit::budget::visit();
    MethodHandleItem item{};
    TRY_U16(item.method_handle_type);
    TRY_U16(item.unused1);
    TRY_U16(item.field_or_method_id);
    TRY_U16(item.unused2);
    method_handles.push_back(item);
  }

  return method_handles;
}

std::expected<TypeList, ParseError> parse_type_list(std::span<const std::uint8_t> buf, uint32_t offset) {
  if (buf.size() < static_cast<std::size_t>(offset) + 4) {
    return std::unexpected(ParseError::truncated_file(offset + 4, static_cast<uint32_t>(buf.size())));
  }

  TypeList type_list{};
  TRY_U32(type_list.size);

  uint64_t total_size = static_cast<uint64_t>(type_list.size) * 2;
  if (type_list.size > 0 && buf.size() < offset + total_size) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(total_size), static_cast<uint32_t>(buf.size())));
  }

  type_list.type_ids.reserve(type_list.size);
  for (uint32_t i = 0; i < type_list.size; ++i) {
    dexsplit::budget::visit();
    uint16_t val{};
    TRY_U16(val);
    type_list.type_ids.push_back(val);
  }

  return type_list;
}

std::expected<ClassDataItem, ParseError> parse_class_data(std::span<const std::uint8_t> buf, uint32_t offset) {
  ClassDataItem item{};

  // Read field and method counts
  uint32_t static_fields_size{};
  uint32_t instance_fields_size{};
  uint32_t direct_methods_size{};
  uint32_t virtual_methods_size{};

  TRY_ULEB128(static_fields_size);
  TRY_ULEB128(instance_fields_size);
  TRY_ULEB128(direct_methods_size);
  TRY_ULEB128(virtual_methods_size);

  // Parse encoded_field lists (field_idx_diff + access_flags)
  auto parse_encoded_fields = [&](uint32_t count,
                                  budget::Vector<EncodedField>& out) -> std::expected<void, ParseError> {
    reserve_bounded(out, count, buf, {offset, 2});  // encoded_field: >= 2 ULEB128 bytes
    uint32_t prev_idx = 0;
    for (uint32_t i = 0; i < count; ++i) {
      dexsplit::budget::visit();
      EncodedField f{};
      uint32_t idx_diff{};
      TRY_ULEB128(idx_diff);
      if (idx_diff > UINT32_MAX - prev_idx || (i != 0 && idx_diff == 0)) {
        return std::unexpected(
            ParseError{ParseError::Code::MalformedData, "member index delta overflow/duplicate", offset});
      }
      prev_idx += idx_diff;
      f.field_idx = prev_idx;
      TRY_ULEB128(f.access_flags);
      out.push_back(f);
    }
    return {};
  };

  // Parse encoded_method lists (method_idx_diff + access_flags + code_off)
  auto parse_encoded_methods = [&](uint32_t count,
                                   budget::Vector<EncodedMethod>& out) -> std::expected<void, ParseError> {
    reserve_bounded(out, count, buf, {offset, 3});  // encoded_method: >= 3 ULEB128 bytes
    uint32_t prev_idx = 0;
    for (uint32_t i = 0; i < count; ++i) {
      dexsplit::budget::visit();
      EncodedMethod m{};
      uint32_t idx_diff{};
      TRY_ULEB128(idx_diff);
      if (idx_diff > UINT32_MAX - prev_idx || (i != 0 && idx_diff == 0)) {
        return std::unexpected(
            ParseError{ParseError::Code::MalformedData, "member index delta overflow/duplicate", offset});
      }
      prev_idx += idx_diff;
      m.method_idx = prev_idx;
      TRY_ULEB128(m.access_flags);
      TRY_ULEB128(m.code_off);
      out.push_back(m);
    }
    return {};
  };

  if (auto r = parse_encoded_fields(static_fields_size, item.static_fields); !r) {
    return std::unexpected(r.error());
  }
  if (auto r = parse_encoded_fields(instance_fields_size, item.instance_fields); !r) {
    return std::unexpected(r.error());
  }
  if (auto r = parse_encoded_methods(direct_methods_size, item.direct_methods); !r) {
    return std::unexpected(r.error());
  }
  if (auto r = parse_encoded_methods(virtual_methods_size, item.virtual_methods); !r) {
    return std::unexpected(r.error());
  }

  return item;
}

std::expected<CodeItem, ParseError> parse_code_item(std::span<const std::uint8_t> buf, uint32_t offset) {
  budget::Scope scope;
  // Minimum code_item header: 4 u16 + 2 u32 = 16 bytes
  if (buf.size() < static_cast<std::size_t>(offset) + 16) {
    return std::unexpected(ParseError::truncated_file(offset + 16, static_cast<uint32_t>(buf.size())));
  }

  CodeItem item{};
  TRY_U16(item.registers_size);
  TRY_U16(item.ins_size);
  TRY_U16(item.outs_size);
  TRY_U16(item.tries_size);
  TRY_U32(item.debug_info_off);
  TRY_U32(item.insns_size);

  // Read instructions (insns_size 16-bit code units)
  uint64_t insns_bytes = static_cast<uint64_t>(item.insns_size) * 2;
  if (item.insns_size > 0 && buf.size() < offset + insns_bytes) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(insns_bytes), static_cast<uint32_t>(buf.size())));
  }
  // The check above covers the whole array, so copy it in one pass instead of
  // one bounds-checked read per code unit.
  item.insns.resize(item.insns_size);
  for (uint32_t i = 0; i < item.insns_size; ++i) {
    dexsplit::budget::visit();
    std::size_t at = static_cast<std::size_t>(offset) + 2 * static_cast<std::size_t>(i);
    item.insns[i] = static_cast<uint16_t>(buf[at] | (buf[at + 1] << 8));
  }
  offset += static_cast<uint32_t>(insns_bytes);

  if (item.tries_size > 0) {
    // tries must start on 4-byte boundary; insert padding if insns_size is odd
    if (item.insns_size % 2 != 0) {
      if (static_cast<std::size_t>(offset) + 2 > buf.size()) {
        return std::unexpected(ParseError::truncated_file(offset + 2, static_cast<uint32_t>(buf.size())));
      }
      if (buf[offset] != 0 || buf[offset + 1] != 0) {
        return std::unexpected(ParseError{ParseError::Code::MalformedData, "nonzero code padding", offset});
      }
      offset += 2;
    }

    // Parse try_items (8 bytes each: u32 start_addr, u16 insn_count, u16 handler_off)
    constexpr uint32_t TRY_ITEM_SIZE = 8;
    uint64_t tries_bytes = static_cast<uint64_t>(item.tries_size) * TRY_ITEM_SIZE;
    if (buf.size() < offset + tries_bytes) {
      return std::unexpected(
          ParseError::truncated_file(offset + static_cast<uint32_t>(tries_bytes), static_cast<uint32_t>(buf.size())));
    }
    item.tries.reserve(item.tries_size);
    for (uint32_t i = 0; i < item.tries_size; ++i) {
      dexsplit::budget::visit();
      TryItem t{};
      TRY_U32(t.start_addr);
      TRY_U16(t.insn_count);
      TRY_U16(t.handler_off);
      item.tries.push_back(t);
    }

    // Parse encoded_catch_handler_list
    // list_size is a ULEB128.  Capture the byte offset of the list start
    // before consuming list_size so each handler's byte offset can be
    // expressed relative to it (matching how TryItem::handler_off is encoded).
    uint32_t list_start_offset = offset;
    uint32_t list_size{};
    TRY_ULEB128(list_size);

    reserve_bounded(item.handlers, list_size, buf, {offset, 1});
    reserve_bounded(item.handler_byte_offsets, list_size, buf, {offset, 1});
    for (uint32_t i = 0; i < list_size; ++i) {
      dexsplit::budget::visit();
      if (offset - list_start_offset > 65535) {
        return std::unexpected(ParseError{ParseError::Code::MalformedData, "catch handler offset overflow", offset});
      }
      item.handler_byte_offsets.push_back(static_cast<uint16_t>(offset - list_start_offset));
      EncodedCatchHandler handler{};

      // Size is a signed LEB128; negative means catch-all present
      uint32_t raw_size{};
      {
        auto _r = parse_utils::read_sleb128(buf, offset);
        if (!_r) {
          return std::unexpected(_r.error());
        }
        raw_size = static_cast<uint32_t>(*_r);
      }
      int32_t signed_size = static_cast<int32_t>(raw_size);
      // Negate in 64 bits: -INT32_MIN does not fit an int32_t.
      int64_t wide_size = signed_size;
      uint32_t pair_count = static_cast<uint32_t>(wide_size < 0 ? -wide_size : wide_size);

      for (uint32_t j = 0; j < pair_count; ++j) {
        dexsplit::budget::visit();
        EncodedTypePair pair{};
        TRY_ULEB128(pair.type_idx);
        TRY_ULEB128(pair.addr);
        handler.handlers.push_back(pair);
      }

      if (signed_size <= 0) {
        uint32_t catch_all{};
        TRY_ULEB128(catch_all);
        handler.catch_all_addr = catch_all;
      }

      item.handlers.push_back(std::move(handler));
    }
  }

  auto structure = validate_code_structure(item);
  if (!structure) {
    return std::unexpected(structure.error());
  }
  item.structure = std::move(*structure);
  item.end_offset = offset;
  return item;
}

std::expected<DebugInfoItem, ParseError> parse_debug_info(std::span<const std::uint8_t> buf, uint32_t offset) {
  // uleb128p1: the stored value is one more than the index, so 0 means none
  // and decrementing it wraps to NO_INDEX.
  auto read_p1 = [&](uint32_t& target) -> std::expected<void, ParseError> {
    auto r = parse_utils::read_uleb128(buf, offset);
    if (!r) {
      return std::unexpected(r.error());
    }
    target = *r - 1;
    return {};
  };

  DebugInfoItem item{};
  TRY_ULEB128(item.line_start);
  uint32_t parameters_size{};
  TRY_ULEB128(parameters_size);
  reserve_bounded(item.parameter_names, parameters_size, buf, {offset, 1});
  for (uint32_t i = 0; i < parameters_size; ++i) {
    dexsplit::budget::visit();
    uint32_t name{};
    if (auto r = read_p1(name); !r) {
      return std::unexpected(r.error());
    }
    item.parameter_names.push_back(name);
  }

  while (true) {
    dexsplit::budget::visit();
    if (offset >= buf.size()) {
      return std::unexpected(ParseError::out_of_bounds(offset, "debug_info_item"));
    }
    DebugOp op{buf[offset++]};
    std::expected<void, ParseError> ok;
    switch (op.opcode) {
      case DBG_END_SEQUENCE:
        return item;
      case DBG_ADVANCE_PC:
        TRY_ULEB128(op.addr_diff);
        break;
      case DBG_ADVANCE_LINE: {
        auto r = parse_utils::read_sleb128(buf, offset);
        if (!r) {
          return std::unexpected(r.error());
        }
        op.line_diff = *r;
        break;
      }
      case DBG_START_LOCAL:
        TRY_ULEB128(op.reg);
        if (ok = read_p1(op.name_idx); ok) {
          ok = read_p1(op.type_idx);
        }
        break;
      case DBG_START_LOCAL_EXTENDED:
        TRY_ULEB128(op.reg);
        if (ok = read_p1(op.name_idx); ok) {
          if (ok = read_p1(op.type_idx); ok) {
            ok = read_p1(op.sig_idx);
          }
        }
        break;
      case DBG_END_LOCAL:
      case DBG_RESTART_LOCAL:
        TRY_ULEB128(op.reg);
        break;
      case DBG_SET_FILE:
        ok = read_p1(op.name_idx);
        break;
      default:  // DBG_SET_PROLOGUE_END, DBG_SET_EPILOGUE_BEGIN, special opcodes
        break;
    }
    if (!ok) {
      return std::unexpected(ok.error());
    }
    item.ops.push_back(op);
  }
}

std::expected<AnnotationsDirectoryItem, ParseError> parse_annotations_directory(std::span<const std::uint8_t> buf,
                                                                                uint32_t offset) {
  // Minimum: 4 u32 = 16 bytes
  if (buf.size() < static_cast<std::size_t>(offset) + 16) {
    return std::unexpected(ParseError::truncated_file(offset + 16, static_cast<uint32_t>(buf.size())));
  }

  AnnotationsDirectoryItem item{};
  TRY_U32(item.class_annotations_off);

  uint32_t fields_size{};
  uint32_t methods_size{};
  uint32_t params_size{};
  TRY_U32(fields_size);
  TRY_U32(methods_size);
  TRY_U32(params_size);

  reserve_bounded(item.field_annotations, fields_size, buf, {offset, 8});  // 2x u32
  for (uint32_t i = 0; i < fields_size; ++i) {
    dexsplit::budget::visit();
    FieldAnnotation fa{};
    TRY_U32(fa.field_idx);
    TRY_U32(fa.annotations_off);
    item.field_annotations.push_back(fa);
  }

  reserve_bounded(item.method_annotations, methods_size, buf, {offset, 8});  // 2x u32
  for (uint32_t i = 0; i < methods_size; ++i) {
    dexsplit::budget::visit();
    MethodAnnotation ma{};
    TRY_U32(ma.method_idx);
    TRY_U32(ma.annotations_off);
    item.method_annotations.push_back(ma);
  }

  reserve_bounded(item.parameter_annotations, params_size, buf, {offset, 8});  // 2x u32
  for (uint32_t i = 0; i < params_size; ++i) {
    dexsplit::budget::visit();
    ParameterAnnotation pa{};
    TRY_U32(pa.method_idx);
    TRY_U32(pa.annotations_off);
    item.parameter_annotations.push_back(pa);
  }

  return item;
}

std::expected<AnnotationSetItem, ParseError> parse_annotation_set(std::span<const std::uint8_t> buf, uint32_t offset) {
  if (buf.size() < static_cast<std::size_t>(offset) + 4) {
    return std::unexpected(ParseError::truncated_file(offset + 4, static_cast<uint32_t>(buf.size())));
  }

  AnnotationSetItem item{};
  uint32_t size{};
  TRY_U32(size);

  uint64_t entries_bytes = static_cast<uint64_t>(size) * 4;
  if (size > 0 && buf.size() < offset + entries_bytes) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(entries_bytes), static_cast<uint32_t>(buf.size())));
  }

  item.entries.reserve(size);
  for (uint32_t i = 0; i < size; ++i) {
    dexsplit::budget::visit();
    uint32_t ann_off{};
    TRY_U32(ann_off);
    item.entries.push_back(ann_off);
  }

  return item;
}

std::expected<AnnotationSetRefList, ParseError> parse_annotation_set_ref_list(std::span<const std::uint8_t> buf,
                                                                              uint32_t offset) {
  if (buf.size() < static_cast<std::size_t>(offset) + 4) {
    return std::unexpected(ParseError::truncated_file(offset + 4, static_cast<uint32_t>(buf.size())));
  }

  AnnotationSetRefList item{};
  uint32_t size{};
  TRY_U32(size);

  uint64_t entries_bytes = static_cast<uint64_t>(size) * 4;
  if (size > 0 && buf.size() < offset + entries_bytes) {
    return std::unexpected(
        ParseError::truncated_file(offset + static_cast<uint32_t>(entries_bytes), static_cast<uint32_t>(buf.size())));
  }

  item.entries.reserve(size);
  for (uint32_t i = 0; i < size; ++i) {
    dexsplit::budget::visit();
    uint32_t set_off{};
    TRY_U32(set_off);
    item.entries.push_back(set_off);
  }

  return item;
}

namespace {

// Arrays and sub-annotations nest; bound the recursion so malformed input
// cannot blow the stack.
constexpr int kMaxEncodedValueDepth = 64;

std::expected<EncodedValue, ParseError> parse_encoded_value_impl(std::span<const std::uint8_t> buf, uint32_t& offset,
                                                                 int depth);

std::expected<EncodedAnnotation, ParseError> parse_encoded_annotation_impl(std::span<const std::uint8_t> buf,
                                                                           uint32_t& offset, int depth) {
  EncodedAnnotation ann;

  auto type_idx = parse_utils::read_uleb128(buf, offset);
  if (!type_idx) {
    return std::unexpected(type_idx.error());
  }
  ann.type_idx = *type_idx;

  auto count = parse_utils::read_uleb128(buf, offset);
  if (!count) {
    return std::unexpected(count.error());
  }

  for (uint32_t i = 0; i < *count; ++i) {
    dexsplit::budget::visit();
    auto name_idx = parse_utils::read_uleb128(buf, offset);
    if (!name_idx) {
      return std::unexpected(name_idx.error());
    }

    auto value = parse_encoded_value_impl(buf, offset, depth);
    if (!value) {
      return std::unexpected(value.error());
    }

    ann.elements.push_back(AnnotationElement{*name_idx, std::move(*value)});
  }
  return ann;
}

// Read `size` little-endian bytes, advancing offset.
std::expected<uint64_t, ParseError> read_le(std::span<const std::uint8_t> buf, uint32_t& offset, unsigned size) {
  if (static_cast<uint64_t>(offset) + size > buf.size()) {
    return std::unexpected(ParseError::truncated_file(offset + size, static_cast<uint32_t>(buf.size())));
  }
  uint64_t v = 0;
  for (unsigned i = 0; i < size; ++i) {
    dexsplit::budget::visit();
    v |= static_cast<uint64_t>(buf[offset + i]) << (8 * i);
  }
  offset += size;
  return v;
}

std::expected<EncodedValue, ParseError> parse_encoded_value_impl(std::span<const std::uint8_t> buf, uint32_t& offset,
                                                                 int depth) {
  if (depth < 0) {
    return std::unexpected(ParseError{ParseError::Code::MalformedData, "encoded_value nesting too deep", offset});
  }
  if (offset >= buf.size()) {
    return std::unexpected(ParseError::truncated_file(offset + 1, static_cast<uint32_t>(buf.size())));
  }

  uint8_t lead = buf[offset++];
  uint8_t arg = lead >> 5;
  auto type = static_cast<EncodedValue::Type>(lead & 0x1f);
  if (depth == 0 && (type == EncodedValue::Type::Array || type == EncodedValue::Type::Annotation)) {
    return std::unexpected(ParseError{ParseError::Code::MalformedData, "encoded_value nesting too deep", offset});
  }

  EncodedValue out;
  out.type = type;

  // Per-type bound on value_arg, from the encoded_value spec.
  auto arg_in_range = [&](uint8_t max) -> bool { return arg <= max; };
  auto malformed = [&](const char* what) {
    return std::unexpected(ParseError{ParseError::Code::MalformedData, what, offset - 1});
  };

  switch (type) {
    case EncodedValue::Type::Byte:
    case EncodedValue::Type::Short:
    case EncodedValue::Type::Int:
    case EncodedValue::Type::Long: {
      uint8_t max_arg = type == EncodedValue::Type::Byte    ? 0
                        : type == EncodedValue::Type::Short ? 1
                        : type == EncodedValue::Type::Int   ? 3
                                                            : 7;
      if (!arg_in_range(max_arg)) {
        return malformed("encoded_value: integer size out of range");
      }
      auto v = read_le(buf, offset, arg + 1u);
      if (!v) {
        return std::unexpected(v.error());
      }
      unsigned shift = 64 - 8 * (arg + 1u);
      out.value = static_cast<int64_t>(*v << shift) >> shift;
      return out;
    }
    case EncodedValue::Type::Char: {
      if (!arg_in_range(1)) {
        return malformed("encoded_value: char size out of range");
      }
      auto v = read_le(buf, offset, arg + 1u);
      if (!v) {
        return std::unexpected(v.error());
      }
      out.value = static_cast<int64_t>(*v);  // zero-extended
      return out;
    }
    case EncodedValue::Type::Float: {
      if (!arg_in_range(3)) {
        return malformed("encoded_value: float size out of range");
      }
      auto v = read_le(buf, offset, arg + 1u);
      if (!v) {
        return std::unexpected(v.error());
      }
      // Bytes fill the most-significant end; low bytes are zero.
      uint32_t bits = static_cast<uint32_t>(*v) << (8 * (3 - arg));
      out.value = static_cast<double>(std::bit_cast<float>(bits));
      return out;
    }
    case EncodedValue::Type::Double: {
      if (!arg_in_range(7)) {
        return malformed("encoded_value: double size out of range");
      }
      auto v = read_le(buf, offset, arg + 1u);
      if (!v) {
        return std::unexpected(v.error());
      }
      uint64_t bits = *v << (8 * (7 - arg));
      out.value = std::bit_cast<double>(bits);
      return out;
    }
    case EncodedValue::Type::MethodType:
    case EncodedValue::Type::MethodHandle:
    case EncodedValue::Type::String:
    case EncodedValue::Type::Type:
    case EncodedValue::Type::Field:
    case EncodedValue::Type::Method:
    case EncodedValue::Type::Enum: {
      if (!arg_in_range(3)) {
        return malformed("encoded_value: index size out of range");
      }
      auto v = read_le(buf, offset, arg + 1u);
      if (!v) {
        return std::unexpected(v.error());
      }
      out.value = static_cast<uint32_t>(*v);  // zero-extended
      return out;
    }
    case EncodedValue::Type::Array: {
      if (arg != 0) {
        return malformed("encoded_value: array with nonzero value_arg");
      }
      auto count = parse_utils::read_uleb128(buf, offset);
      if (!count) {
        return std::unexpected(count.error());
      }
      budget::Vector<EncodedValue> items;
      for (uint32_t i = 0; i < *count; ++i) {
        dexsplit::budget::visit();
        auto item = parse_encoded_value_impl(buf, offset, depth - 1);
        if (!item) {
          return std::unexpected(item.error());
        }
        items.push_back(std::move(*item));
      }
      out.value = std::move(items);
      return out;
    }
    case EncodedValue::Type::Annotation: {
      if (arg != 0) {
        return malformed("encoded_value: annotation with nonzero value_arg");
      }
      auto ann = parse_encoded_annotation_impl(buf, offset, depth - 1);
      if (!ann) {
        return std::unexpected(ann.error());
      }
      out.value = budget::make_shared<EncodedAnnotation>(std::move(*ann));
      return out;
    }
    case EncodedValue::Type::Null:
      if (arg != 0) {
        return malformed("encoded_value: null with nonzero value_arg");
      }
      out.value = std::monostate{};
      return out;
    case EncodedValue::Type::Boolean:
      if (!arg_in_range(1)) {
        return malformed("encoded_value: boolean value_arg out of range");
      }
      out.value = (arg != 0);
      return out;
  }
  return malformed("encoded_value: unknown value_type");
}

}  // namespace

std::expected<EncodedValue, ParseError> parse_encoded_value(std::span<const std::uint8_t> buf, uint32_t& offset) {
  return parse_encoded_value_impl(buf, offset, kMaxEncodedValueDepth);
}

std::expected<budget::Vector<EncodedValue>, ParseError> parse_encoded_array(std::span<const std::uint8_t> buf,
                                                                            uint32_t& offset) {
  auto count = parse_utils::read_uleb128(buf, offset);
  if (!count) {
    return std::unexpected(count.error());
  }

  budget::Vector<EncodedValue> items;
  for (uint32_t i = 0; i < *count; ++i) {
    dexsplit::budget::visit();
    auto item = parse_encoded_value_impl(buf, offset, kMaxEncodedValueDepth);
    if (!item) {
      return std::unexpected(item.error());
    }
    items.push_back(std::move(*item));
  }
  return items;
}

std::expected<EncodedAnnotation, ParseError> parse_encoded_annotation(std::span<const std::uint8_t> buf,
                                                                      uint32_t& offset) {
  return parse_encoded_annotation_impl(buf, offset, kMaxEncodedValueDepth);
}

std::expected<AnnotationItem, ParseError> parse_annotation_item(std::span<const std::uint8_t> buf, uint32_t offset) {
  if (offset >= buf.size()) {
    return std::unexpected(ParseError::truncated_file(offset + 1, static_cast<uint32_t>(buf.size())));
  }

  AnnotationItem item;
  item.visibility = buf[offset++];

  auto ann = parse_encoded_annotation_impl(buf, offset, kMaxEncodedValueDepth);
  if (!ann) {
    return std::unexpected(ann.error());
  }
  item.annotation = std::move(*ann);
  return item;
}

std::expected<uint32_t, ParseError> compute_checksum(std::span<const uint8_t> buf) {
  // Adler-32 covers bytes from offset 12 onwards (skips magic[8] + checksum[4])
  constexpr uint32_t ADLER_MOD = 65521;
  constexpr uint32_t SKIP = 12;

  if (buf.size() < SKIP) {
    return std::unexpected(ParseError::truncated_file(SKIP, static_cast<uint32_t>(buf.size())));
  }

  // Reduce modulo ADLER_MOD once per block: 5552 is the largest block length
  // for which `b` cannot overflow 32 bits (the zlib NMAX bound).
  constexpr std::size_t BLOCK = 5552;
  uint32_t a = 1;
  uint32_t b = 0;
  for (std::size_t i = SKIP; i < buf.size();) {
    std::size_t end = std::min(buf.size(), i + BLOCK);
    for (; i < end; ++i) {
      a += buf[i];
      b += a;
    }
    a %= ADLER_MOD;
    b %= ADLER_MOD;
  }

  return (b << 16) | a;
}

std::expected<std::array<uint8_t, 20>, ParseError> compute_signature(std::span<const uint8_t> buf) {
  // The signature covers everything after magic[8], checksum[4] and itself[20].
  constexpr uint32_t SKIP = 32;
  if (buf.size() < SKIP) {
    return std::unexpected(ParseError::truncated_file(SKIP, static_cast<uint32_t>(buf.size())));
  }
  return sha1(buf.subspan(SKIP));
}

std::expected<DexFile, ParseError> parse_buffer(std::span<const uint8_t> buffer, ParseOptions options) {
  budget::Scope scope;
  auto layout = parse_layout(buffer);
  if (!layout) {
    return std::unexpected(layout.error());
  }
  auto header_result = parse_header(buffer);
  if (!header_result) {
    return std::unexpected(header_result.error());
  }

  DexFile dex;
  dex.header_ = *header_result;
  dex.code_items_ = std::move(*layout);

  auto map_result = parse_map_list(buffer, dex.header_.map_off);
  if (!map_result) {
    return std::unexpected(map_result.error());
  }
  dex.map_list_ = std::move(*map_result);

  if (dex.header_.string_ids_size > 0) {
    auto r = parse_string_ids(buffer, dex.header_.string_ids_off, dex.header_.string_ids_size);
    if (!r) {
      return std::unexpected(r.error());
    }
    dex.string_ids_ = std::move(*r);
  }

  if (dex.header_.type_ids_size > 0) {
    auto r = parse_type_ids(buffer, dex.header_.type_ids_off, dex.header_.type_ids_size);
    if (!r) {
      return std::unexpected(r.error());
    }
    dex.type_ids_ = std::move(*r);
  }

  if (dex.header_.proto_ids_size > 0) {
    auto r = parse_proto_ids(buffer, dex.header_.proto_ids_off, dex.header_.proto_ids_size);
    if (!r) {
      return std::unexpected(r.error());
    }
    dex.proto_ids_ = std::move(*r);
  }

  if (dex.header_.field_ids_size > 0) {
    auto r = parse_field_ids(buffer, dex.header_.field_ids_off, dex.header_.field_ids_size);
    if (!r) {
      return std::unexpected(r.error());
    }
    dex.field_ids_ = std::move(*r);
  }

  if (dex.header_.method_ids_size > 0) {
    auto r = parse_method_ids(buffer, dex.header_.method_ids_off, dex.header_.method_ids_size);
    if (!r) {
      return std::unexpected(r.error());
    }
    dex.method_ids_ = std::move(*r);
  }

  if (dex.header_.class_defs_size > 0) {
    auto r = parse_class_defs(buffer, dex.header_.class_defs_off, dex.header_.class_defs_size);
    if (!r) {
      return std::unexpected(r.error());
    }
    dex.class_defs_ = std::move(*r);
  }

  // Optional sections: find call_site_ids and method_handles from map list
  for (const auto& item : dex.map_list_.items) {
    dexsplit::budget::visit();
    if (item.type == TYPE_CALL_SITE_ID_ITEM && item.size > 0) {
      auto r = parse_call_site_ids(buffer, item.offset, item.size);
      if (!r) {
        return std::unexpected(r.error());
      }
      dex.call_site_ids_ = std::move(*r);
    } else if (item.type == TYPE_METHOD_HANDLE_ITEM && item.size > 0) {
      auto r = parse_method_handles(buffer, item.offset, item.size);
      if (!r) {
        return std::unexpected(r.error());
      }
      dex.method_handles_ = std::move(*r);
    }
  }

  if (options.decode_strings) {
    auto strings_result = parse_strings(buffer, dex.string_ids_);
    if (!strings_result) {
      return std::unexpected(strings_result.error());
    }
    dex.strings_ = std::move(*strings_result);
  }

  return dex;
}

std::expected<DexFile, ParseError> parse_file(const budget::String& path, ParseOptions options) {
  budget::Scope scope;
  std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    return std::unexpected(ParseError{ParseError::Code::NullPointer, "Cannot open file: " + path, 0});
  }

  auto length = file.tellg();
  if (length < 0 || static_cast<uint64_t>(length) > budget::kDexBytes) {
    return std::unexpected(ParseError{ParseError::Code::InvalidSize, "DEX input byte limit", 0});
  }
  auto size = static_cast<std::size_t>(length);
  file.seekg(0);

  budget::Vector<uint8_t> buffer(size);
  file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));

  if (!file) {
    return std::unexpected(ParseError{ParseError::Code::TruncatedFile, "Failed to read file: " + path, 0});
  }

  return parse_buffer(std::span<const uint8_t>(buffer), options);
}

}  // namespace dexsplit::raw::parser

#undef TRY_U32
#undef TRY_U16
#undef TRY_ULEB128
#undef SKIP_ULEB128
#undef TRY_MUTF8
