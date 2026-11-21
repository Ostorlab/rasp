#include "util/property_area.h"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "util/raw_file.h"

namespace rasp::android::util {

namespace {

/// The `property_info` version this reader understands.
constexpr std::uint32_t kInfoVersion = 1;
/// What `property_info` stores for an entry that names no property file.
constexpr std::uint32_t kNoContext = 0xFFFFFFFFU;
/// The magic a property file starts with, "PROP".
constexpr std::uint32_t kAreaMagic = 0x504F5250U;
/// The property file layout version this reader understands.
constexpr std::uint32_t kAreaVersion = 0xFC6ED0ABU;
/// Where a property file's trie starts, after its header.
constexpr std::size_t kAreaDataOffset = 128;
/// The size of a trie node before its name.
constexpr std::uint32_t kNodeSize = 20;
/// The size of a short value, its terminating zero included.
constexpr std::uint32_t kValueSize = 92;
/// Where a long value's offset sits in a property, after its serial and its error message.
constexpr std::uint32_t kLongOffsetPosition = 60;
/// The serial flag of a property whose value is stored elsewhere because it is long.
constexpr std::uint32_t kLongFlag = 1U << 16U;
/// The serial flag of a property that is being written.
constexpr std::uint32_t kDirtyFlag = 1U;
/// The serial bits that count the writes after the first one.
constexpr std::uint32_t kUpdateCounter = 0x00FFFFFFU & ~kLongFlag & ~kDirtyFlag;
/// The tries of a property file are walked at most this many steps for one name segment, against a crafted cycle.
constexpr std::size_t kMaxSiblingSteps = 4096;
/// How many times a value being written is read again.
constexpr int kReadAttempts = 8;
/// The largest property file or index mapped.
constexpr std::size_t kMaxFileSize = std::size_t{1} << 20U;
/// The largest memory map read.
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;

[[nodiscard]] std::optional<std::uint32_t> read_u32(std::string_view bytes, std::uint64_t offset) {
  if (offset > bytes.size() || bytes.size() - offset < sizeof(std::uint32_t)) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  std::memcpy(&value, bytes.substr(static_cast<std::size_t>(offset), sizeof(value)).data(), sizeof(value));
  return value;
}

/// The `length` characters of `bytes` at `offset`.
[[nodiscard]] std::optional<std::string_view> chars(std::string_view bytes, std::uint64_t offset,
                                                    std::uint64_t length) {
  if (offset > bytes.size() || bytes.size() - offset < length) {
    return std::nullopt;
  }
  return bytes.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(length));
}

/// The zero-terminated string of `bytes` at `offset`.
[[nodiscard]] std::optional<std::string_view> c_string(std::string_view bytes, std::uint64_t offset) {
  if (offset > bytes.size()) {
    return std::nullopt;
  }
  const std::string_view rest = bytes.substr(static_cast<std::size_t>(offset));
  const std::size_t end = rest.find('\0');
  if (end == std::string_view::npos) {
    return std::nullopt;
  }
  return rest.substr(0, end);
}

/// One entry of `property_info`: a name and the property file it maps to.
struct InfoEntry {
  std::string_view name;
  std::uint32_t context = kNoContext;
};

/// One trie node of `property_info`.
struct InfoNode {
  std::uint32_t entry = 0;
  std::uint32_t child_count = 0;
  std::uint32_t children = 0;
  std::uint32_t prefix_count = 0;
  std::uint32_t prefixes = 0;
  std::uint32_t exact_count = 0;
  std::uint32_t exacts = 0;
};

/// A parsed view of `property_info`.
class PropertyInfo {
 public:
  explicit PropertyInfo(std::string_view bytes) : bytes_(bytes) {}

  [[nodiscard]] std::optional<InfoEntry> entry(std::uint32_t offset) const {
    const auto name_offset = read_u32(bytes_, offset);
    const auto name_length = read_u32(bytes_, std::uint64_t{offset} + 4);
    const auto context = read_u32(bytes_, std::uint64_t{offset} + 8);
    if (!name_offset || !name_length || !context) {
      return std::nullopt;
    }
    const std::optional<std::string_view> name = chars(bytes_, *name_offset, *name_length);
    if (!name) {
      return std::nullopt;
    }
    return InfoEntry{.name = *name, .context = *context};
  }

  [[nodiscard]] std::optional<InfoNode> node(std::uint32_t offset) const {
    std::array<std::uint32_t, 7> fields{};
    for (std::size_t index = 0; index < fields.size(); ++index) {
      const std::optional<std::uint32_t> field = read_u32(bytes_, std::uint64_t{offset} + (std::uint64_t{4} * index));
      if (!field) {
        return std::nullopt;
      }
      fields.at(index) = *field;
    }
    return InfoNode{
        .entry = fields[0],
        .child_count = fields[1],
        .children = fields[2],
        .prefix_count = fields[3],
        .prefixes = fields[4],
        .exact_count = fields[5],
        .exacts = fields[6],
    };
  }

  /// The element `index` of the offset array at `array`.
  [[nodiscard]] std::optional<std::uint32_t> element(std::uint32_t array, std::uint32_t index) const {
    return read_u32(bytes_, std::uint64_t{array} + (std::uint64_t{4} * index));
  }

  /// The name of the property file `context` stands for.
  [[nodiscard]] std::optional<std::string_view> context_name(std::uint32_t context) const {
    const std::optional<std::uint32_t> contexts = read_u32(bytes_, 12);
    const std::optional<std::uint32_t> count = contexts ? read_u32(bytes_, *contexts) : std::nullopt;
    if (!count || context >= *count) {
      return std::nullopt;
    }
    const std::optional<std::uint32_t> offset = element(*contexts + 4, context);
    return offset ? c_string(bytes_, *offset) : std::nullopt;
  }

  /// The child of `node` named `segment`, by binary search over the sorted children.
  [[nodiscard]] std::optional<InfoNode> child(const InfoNode& node, std::string_view segment) const {
    std::uint32_t low = 0;
    std::uint32_t high = node.child_count;
    while (low < high) {
      const std::uint32_t middle = low + ((high - low) / 2);
      const std::optional<std::uint32_t> offset = element(node.children, middle);
      const std::optional<InfoNode> candidate = offset ? this->node(*offset) : std::nullopt;
      const std::optional<InfoEntry> name = candidate ? entry(candidate->entry) : std::nullopt;
      if (!name) {
        return std::nullopt;
      }
      if (name->name == segment) {
        return candidate;
      }
      if (name->name < segment) {
        low = middle + 1;
      } else {
        high = middle;
      }
    }
    return std::nullopt;
  }

  /// The context of the first of `node`'s prefixes that `rest` starts with, or `found` when none does.
  [[nodiscard]] std::optional<std::uint32_t> prefix_context(const InfoNode& node, std::string_view rest,
                                                            std::uint32_t found) const {
    for (std::uint32_t index = 0; index < node.prefix_count; ++index) {
      const std::optional<std::uint32_t> offset = element(node.prefixes, index);
      const std::optional<InfoEntry> prefix = offset ? entry(*offset) : std::nullopt;
      if (!prefix) {
        return std::nullopt;
      }
      if (rest.starts_with(prefix->name)) {
        return prefix->context != kNoContext ? prefix->context : found;
      }
    }
    return found;
  }

  /// The context of the exact match `rest` has among `node`'s, or nothing when none matches.
  [[nodiscard]] std::optional<std::optional<std::uint32_t>> exact_context(const InfoNode& node,
                                                                          std::string_view rest) const {
    for (std::uint32_t index = 0; index < node.exact_count; ++index) {
      const std::optional<std::uint32_t> offset = element(node.exacts, index);
      const std::optional<InfoEntry> exact = offset ? entry(*offset) : std::nullopt;
      if (!exact) {
        return std::optional<std::uint32_t>();
      }
      if (exact->name == rest) {
        return std::optional<std::uint32_t>(exact->context);
      }
    }
    return std::nullopt;
  }

 private:
  std::string_view bytes_;
};

/// Looks `name` up in `info` as the platform does: the deepest matching node's context, overridden by a longer prefix
/// or an exact match.
[[nodiscard]] std::optional<std::uint32_t> lookup_context(const PropertyInfo& info, std::uint32_t root,
                                                          std::string_view name) {
  std::optional<InfoNode> node = info.node(root);
  std::uint32_t found = kNoContext;
  std::string_view rest = name;
  while (node) {
    const std::optional<InfoEntry> own = info.entry(node->entry);
    if (!own) {
      return std::nullopt;
    }
    if (own->context != kNoContext) {
      found = own->context;
    }
    const std::optional<std::uint32_t> prefixed = info.prefix_context(*node, rest, found);
    if (!prefixed) {
      return std::nullopt;
    }
    found = *prefixed;
    const std::size_t dot = rest.find('.');
    if (dot == std::string_view::npos) {
      break;
    }
    const std::optional<InfoNode> next = info.child(*node, rest.substr(0, dot));
    if (!next) {
      break;
    }
    node = next;
    rest.remove_prefix(dot + 1);
  }
  if (!node) {
    return std::nullopt;
  }
  if (const std::optional<std::optional<std::uint32_t>> exact = info.exact_context(*node, rest)) {
    if (!*exact) {
      return std::nullopt;
    }
    return **exact != kNoContext ? **exact : found;
  }
  return info.prefix_context(*node, rest, found);
}

/// One trie node of a property file.
struct AreaNode {
  std::string_view name;
  std::uint32_t property = 0;
  std::uint32_t left = 0;
  std::uint32_t right = 0;
  std::uint32_t children = 0;
};

[[nodiscard]] std::optional<AreaNode> area_node(std::string_view data, std::uint32_t offset) {
  std::array<std::uint32_t, 5> fields{};
  for (std::size_t index = 0; index < fields.size(); ++index) {
    const std::optional<std::uint32_t> field = read_u32(data, std::uint64_t{offset} + (std::uint64_t{4} * index));
    if (!field) {
      return std::nullopt;
    }
    fields.at(index) = *field;
  }
  const std::optional<std::string_view> name = chars(data, std::uint64_t{offset} + kNodeSize, fields[0]);
  if (!name) {
    return std::nullopt;
  }
  return AreaNode{.name = *name, .property = fields[1], .left = fields[2], .right = fields[3], .children = fields[4]};
}

/// Orders two name segments as the platform does: by length first, then byte by byte.
[[nodiscard]] int compare_segments(std::string_view one, std::string_view two) {
  if (one.size() != two.size()) {
    return one.size() < two.size() ? -1 : 1;
  }
  return one.compare(two);
}

/// The node named `segment` among the siblings of the binary tree at `offset`.
[[nodiscard]] std::optional<AreaNode> sibling(std::string_view data, std::uint32_t offset, std::string_view segment) {
  for (std::size_t step = 0; step < kMaxSiblingSteps && offset != 0; ++step) {
    const std::optional<AreaNode> node = area_node(data, offset);
    if (!node) {
      return std::nullopt;
    }
    const int order = compare_segments(segment, node->name);
    if (order == 0) {
      return node;
    }
    offset = order < 0 ? node->left : node->right;
  }
  return std::nullopt;
}

/// The value and serial of the property at `offset`, read again while it is being written.
[[nodiscard]] std::optional<AreaProperty> read_property(std::string_view data, std::uint32_t offset) {
  for (int attempt = 0; attempt < kReadAttempts; ++attempt) {
    const std::optional<std::uint32_t> serial = read_u32(data, offset);
    if (!serial) {
      return std::nullopt;
    }
    std::optional<std::string_view> value;
    if ((*serial & kLongFlag) != 0) {
      const std::optional<std::uint32_t> long_offset = read_u32(data, std::uint64_t{offset} + kLongOffsetPosition);
      value = long_offset ? c_string(data, std::uint64_t{offset} + *long_offset) : std::nullopt;
    } else {
      const std::uint64_t length = *serial >> 24U;
      value = length < kValueSize ? chars(data, std::uint64_t{offset} + 4, length) : std::nullopt;
    }
    if (!value) {
      return std::nullopt;
    }
    AreaProperty property{.value = std::string(*value), .serial = *serial};
    if ((*serial & kDirtyFlag) == 0 && read_u32(data, offset) == serial) {
      return property;
    }
  }
  return std::nullopt;
}

/// The address range and permissions of a memory-map line, and its pathname.
struct MapLine {
  std::string_view range;
  std::string_view permissions;
  std::string_view pathname;
};

[[nodiscard]] MapLine parse_map_line(std::string_view line) {
  MapLine parsed;
  std::string_view rest = line;
  for (int field = 0; field < 5; ++field) {
    const std::size_t end = std::min(rest.find(' '), rest.size());
    if (field == 0) {
      parsed.range = rest.substr(0, end);
    } else if (field == 1) {
      parsed.permissions = rest.substr(0, end);
    }
    rest.remove_prefix(end);
    rest.remove_prefix(std::min(rest.find_first_not_of(' '), rest.size()));
  }
  parsed.pathname = rest;
  return parsed;
}

[[nodiscard]] std::optional<std::uintptr_t> parse_address(std::string_view text) {
  std::uintptr_t value = 0;
  const char* const last = std::to_address(text.end());
  const auto [stop, error] = std::from_chars(std::to_address(text.begin()), last, value, 16);
  if (text.empty() || error != std::errc{} || stop != last) {
    return std::nullopt;
  }
  return value;
}

}  // namespace

std::optional<std::string_view> PropertyIndex::file_of(std::string_view name) const {
  const std::optional<std::uint32_t> minimum_version = read_u32(bytes_, 4);
  const std::optional<std::uint32_t> size = read_u32(bytes_, 8);
  const std::optional<std::uint32_t> root = read_u32(bytes_, 20);
  if (!minimum_version || !size || !root || *minimum_version > kInfoVersion || *size > bytes_.size()) {
    return std::nullopt;
  }
  const PropertyInfo parsed(bytes_.substr(0, *size));
  const std::optional<std::uint32_t> context = lookup_context(parsed, *root, name);
  if (!context || *context == kNoContext) {
    return std::nullopt;
  }
  return parsed.context_name(*context);
}

std::optional<AreaProperty> PropertyFile::find(std::string_view name) const {
  if (bytes_.size() < kAreaDataOffset || read_u32(bytes_, 8) != kAreaMagic || read_u32(bytes_, 12) != kAreaVersion) {
    return std::nullopt;
  }
  const std::string_view data = bytes_.substr(kAreaDataOffset);
  std::optional<AreaNode> node = area_node(data, 0);
  for (const auto piece : std::views::split(name, '.')) {
    const std::string_view segment(piece.begin(), piece.end());
    if (!node || segment.empty() || node->children == 0) {
      return std::nullopt;
    }
    node = sibling(data, node->children, segment);
  }
  if (!node || node->property == 0) {
    return std::nullopt;
  }
  return read_property(data, node->property);
}

bool was_rewritten(std::uint32_t serial) { return (serial & kUpdateCounter) != 0; }

PropertyAreas::PropertyAreas(std::string directory, std::string maps_path, rasp::util::ProcReader read)
    : directory_(std::move(directory)), maps_path_(std::move(maps_path)), read_(read) {}

bool PropertyAreas::readable() {
  if (!opened_) {
    opened_ = true;
    info_ = area("property_info");
  }
  return !info_.empty();
}

std::optional<AreaProperty> PropertyAreas::read(std::string_view name) {
  if (!readable()) {
    return std::nullopt;
  }
  const std::optional<std::string_view> file = PropertyIndex(info_).file_of(name);
  if (!file || file->contains('/')) {
    return std::nullopt;
  }
  const std::string_view bytes = area(*file);
  if (bytes.empty()) {
    return std::nullopt;
  }
  return PropertyFile(bytes).find(name);
}

std::string_view PropertyAreas::area(std::string_view file) {
  const auto cached =
      std::ranges::find_if(areas_, [file](const auto& entry) { return std::string_view(entry.first) == file; });
  if (cached != areas_.end()) {
    return cached->second;
  }
  const std::string path = directory_ + "/" + std::string(file);
  std::string_view bytes;
  std::optional<rasp::util::MappedFile> mapping = rasp::util::MappedFile::map(path, kMaxFileSize);
  if (mapping) {
    bytes = mapping->bytes();
    mappings_.push_back(std::move(*mapping));
  } else {
    bytes = mapped_by_process(path);
  }
  areas_.emplace_back(std::string(file), bytes);
  return bytes;
}

std::string_view PropertyAreas::mapped_by_process(std::string_view path) {
  if (!maps_) {
    maps_ = read_(maps_path_, kMaxMapsSize).value_or(std::string());
  }
  for (const auto piece : std::views::split(std::string_view(*maps_), '\n')) {
    const MapLine line = parse_map_line(std::string_view(piece.begin(), piece.end()));
    const std::size_t dash = line.range.find('-');
    if (line.pathname != path || !line.permissions.starts_with('r') || dash == std::string_view::npos) {
      continue;
    }
    const std::optional<std::uintptr_t> start = parse_address(line.range.substr(0, dash));
    const std::optional<std::uintptr_t> end = parse_address(line.range.substr(dash + 1));
    if (start && end && *start < *end) {
      return {std::bit_cast<const char*>(*start), static_cast<std::size_t>(*end - *start)};
    }
  }
  return {};
}

}  // namespace rasp::android::util
