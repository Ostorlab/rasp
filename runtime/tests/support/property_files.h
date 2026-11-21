/// Builders of the platform's property files and of their `property_info` index, for the tests.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rasp::test_support {

/// One property of a property file.
struct FileProperty {
  std::string name;
  std::string value;
  /// The serial's update counter: 0 for a property set once.
  std::uint32_t counter = 0;
};

namespace property_files {

/// Writes `value` at `offset` of `bytes`, growing it when needed.
inline void put_u32(std::string& bytes, std::size_t offset, std::uint32_t value) {
  if (bytes.size() < offset + sizeof(value)) {
    bytes.resize(offset + sizeof(value), '\0');
  }
  std::memcpy(bytes.data() + offset, &value, sizeof(value));  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

/// Reads the value at `offset` of `bytes`.
[[nodiscard]] inline std::uint32_t get_u32(const std::string& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  std::memcpy(&value, bytes.data() + offset, sizeof(value));  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return value;
}

/// Appends `size` zero bytes to `data`, aligned as the platform aligns them, and returns where they start.
inline std::uint32_t allocate(std::string& data, std::size_t size) {
  const auto offset = static_cast<std::uint32_t>(data.size());
  data.resize(data.size() + ((size + 3U) & ~std::size_t{3}), '\0');
  return offset;
}

/// Appends a trie node named `name` to `data` and returns its offset.
inline std::uint32_t add_node(std::string& data, std::string_view name) {
  const std::uint32_t offset = allocate(data, 20 + name.size() + 1);
  put_u32(data, offset, static_cast<std::uint32_t>(name.size()));
  data.replace(offset + 20, name.size(), name);
  return offset;
}

/// Orders two name segments as the platform does: by length first, then byte by byte.
[[nodiscard]] inline int compare(std::string_view one, std::string_view two) {
  if (one.size() != two.size()) {
    return one.size() < two.size() ? -1 : 1;
  }
  return one.compare(two);
}

/// The node named `segment` among the children of the node at `parent`, added when it is missing.
inline std::uint32_t child(std::string& data, std::uint32_t parent, std::string_view segment) {
  constexpr std::size_t kChildren = 16;
  std::size_t link = parent + kChildren;
  while (get_u32(data, link) != 0) {
    const std::uint32_t node = get_u32(data, link);
    const std::string_view name(data.data() + node + 20, get_u32(data, node));  // NOLINT
    const int order = compare(segment, name);
    if (order == 0) {
      return node;
    }
    link = node + (order < 0 ? 8U : 12U);
  }
  const std::uint32_t node = add_node(data, segment);
  put_u32(data, link, node);
  return node;
}

}  // namespace property_files

/// The bytes of a property file that holds `properties`, laid out as the platform lays them out.
[[nodiscard]] inline std::string property_file(std::span<const FileProperty> properties) {
  using namespace property_files;
  constexpr std::uint32_t kValueSize = 92;
  constexpr std::uint32_t kLongFlag = 1U << 16U;
  std::string data;
  allocate(data, 20 + kValueSize);
  for (const FileProperty& property : properties) {
    std::uint32_t node = 0;
    std::string_view rest = property.name;
    while (!rest.empty()) {
      const std::size_t dot = std::min(rest.find('.'), rest.size());
      node = child(data, node, rest.substr(0, dot));
      rest.remove_prefix(std::min(dot + 1, rest.size()));
    }
    const bool is_long = property.value.size() >= kValueSize;
    const std::uint32_t info = allocate(data, 4 + kValueSize + property.name.size() + 1);
    data.replace(info + 4 + kValueSize, property.name.size(), property.name);
    if (is_long) {
      const std::uint32_t value = allocate(data, property.value.size() + 1);
      data.replace(value, property.value.size(), property.value);
      put_u32(data, info, kLongFlag | property.counter);
      put_u32(data, info + 60, value - info);
    } else {
      put_u32(data, info, (static_cast<std::uint32_t>(property.value.size()) << 24U) | property.counter);
      data.replace(info + 4, property.value.size(), property.value);
    }
    put_u32(data, node + 4, info);
  }
  std::string area(128, '\0');
  put_u32(area, 0, static_cast<std::uint32_t>(data.size()));
  put_u32(area, 8, 0x504F5250U);
  put_u32(area, 12, 0xFC6ED0ABU);
  return area + data;
}

/// One node of a `property_info` trie, in a list of nodes whose first is the root.
struct InfoNode {
  std::string name;
  std::optional<std::uint32_t> context;
  /// The prefixes that end at this node and their contexts, the longest first.
  std::vector<std::pair<std::string, std::uint32_t>> prefixes;
  /// The exact names that end at this node and their contexts.
  std::vector<std::pair<std::string, std::uint32_t>> exact_matches;
  /// The positions of the child nodes in the list, sorted by the children's names. A child comes after its parent.
  std::vector<std::size_t> children;
};

namespace property_files {

/// Appends `text` and its terminating zero to `bytes`, and returns where it starts.
inline std::uint32_t add_string(std::string& bytes, std::string_view text) {
  const auto offset = static_cast<std::uint32_t>(bytes.size());
  bytes.append(text);
  bytes.push_back('\0');
  bytes.resize((bytes.size() + 3U) & ~std::size_t{3}, '\0');
  return offset;
}

/// Appends a property entry to `bytes` and returns where it starts.
inline std::uint32_t add_entry(std::string& bytes, std::string_view name, std::optional<std::uint32_t> context) {
  const std::uint32_t name_offset = add_string(bytes, name);
  const auto offset = static_cast<std::uint32_t>(bytes.size());
  put_u32(bytes, offset, name_offset);
  put_u32(bytes, offset + 4, static_cast<std::uint32_t>(name.size()));
  put_u32(bytes, offset + 8, context.value_or(0xFFFFFFFFU));
  put_u32(bytes, offset + 12, 0xFFFFFFFFU);
  return offset;
}

/// Appends an array of `offsets` to `bytes` and returns where it starts.
inline std::uint32_t add_array(std::string& bytes, const std::vector<std::uint32_t>& offsets) {
  const auto offset = static_cast<std::uint32_t>(bytes.size());
  for (std::size_t index = 0; index < offsets.size(); ++index) {
    put_u32(bytes, offset + (4 * index), offsets[index]);
  }
  return offset;
}

/// Appends the entries of `pairs` to `bytes` and returns their offsets.
inline std::vector<std::uint32_t> add_entries(std::string& bytes,
                                              const std::vector<std::pair<std::string, std::uint32_t>>& pairs) {
  std::vector<std::uint32_t> offsets;
  offsets.reserve(pairs.size());
  for (const auto& [name, context] : pairs) {
    offsets.push_back(add_entry(bytes, name, context));
  }
  return offsets;
}

}  // namespace property_files

/// The bytes of a `property_info` index that names the property files `contexts` and maps names to them by the trie
/// `nodes`, whose first node is the root.
[[nodiscard]] inline std::string property_info(std::span<const std::string> contexts, std::span<const InfoNode> nodes) {
  using namespace property_files;
  std::string bytes(24, '\0');
  std::vector<std::uint32_t> names;
  names.reserve(contexts.size());
  for (const std::string& context : contexts) {
    names.push_back(add_string(bytes, context));
  }
  const auto contexts_offset = static_cast<std::uint32_t>(bytes.size());
  put_u32(bytes, contexts_offset, static_cast<std::uint32_t>(names.size()));
  add_array(bytes, names);
  std::vector<std::uint32_t> offsets(nodes.size(), 0);
  for (std::size_t position = nodes.size(); position-- > 0;) {
    const InfoNode& node = nodes[position];
    std::vector<std::uint32_t> children;
    children.reserve(node.children.size());
    for (const std::size_t child : node.children) {
      children.push_back(offsets.at(child));
    }
    const std::vector<std::uint32_t> prefixes = add_entries(bytes, node.prefixes);
    const std::vector<std::uint32_t> exact_matches = add_entries(bytes, node.exact_matches);
    const std::uint32_t entry = add_entry(bytes, node.name, node.context);
    const std::uint32_t child_array = add_array(bytes, children);
    const std::uint32_t prefix_array = add_array(bytes, prefixes);
    const std::uint32_t exact_array = add_array(bytes, exact_matches);
    const auto offset = static_cast<std::uint32_t>(bytes.size());
    put_u32(bytes, offset, entry);
    put_u32(bytes, offset + 4, static_cast<std::uint32_t>(children.size()));
    put_u32(bytes, offset + 8, child_array);
    put_u32(bytes, offset + 12, static_cast<std::uint32_t>(prefixes.size()));
    put_u32(bytes, offset + 16, prefix_array);
    put_u32(bytes, offset + 20, static_cast<std::uint32_t>(exact_matches.size()));
    put_u32(bytes, offset + 24, exact_array);
    offsets.at(position) = offset;
  }
  put_u32(bytes, 0, 1);
  put_u32(bytes, 4, 1);
  put_u32(bytes, 8, static_cast<std::uint32_t>(bytes.size()));
  put_u32(bytes, 12, contexts_offset);
  put_u32(bytes, 20, nodes.empty() ? 0 : offsets.front());
  return bytes;
}

}  // namespace rasp::test_support
