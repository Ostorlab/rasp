/// parse_config: reads the runtime's config with yyjson.

#include "rasp/parse_config.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <yyjson.h>

#include "rasp/config.h"

namespace rasp {

namespace {

/// Reads a JSON string.
///
/// @param value The value, or null.
/// @return The string. Empty when `value` is null or is not a string.
[[nodiscard]] std::string read_text(const yyjson_val* value) {
  if (!yyjson_is_str(value)) {
    return {};
  }
  return {yyjson_get_str(value), yyjson_get_len(value)};
}

/// Reads a JSON string an optional field carries.
///
/// @param value The value, or null.
/// @return The string. Nothing when `value` is null or is not a string, which leaves the field at
/// its default, the way a config the packer wrote without the field reads.
[[nodiscard]] std::optional<std::string> read_optional_text(const yyjson_val* value) {
  if (!yyjson_is_str(value)) {
    return std::nullopt;
  }
  return read_text(value);
}

/// Reads a JSON array of strings.
///
/// @param value The value, or null.
/// @return The array's strings, in its order, without its items that are not strings. Nothing when `value` is null or
/// is not an array.
[[nodiscard]] std::optional<std::vector<std::string>> read_texts(const yyjson_val* value) {
  if (!yyjson_is_arr(value)) {
    return std::nullopt;
  }
  std::vector<std::string> texts;
  yyjson_arr_iter items = yyjson_arr_iter_with(value);
  for (const yyjson_val* item = yyjson_arr_iter_next(&items); item != nullptr; item = yyjson_arr_iter_next(&items)) {
    if (yyjson_is_str(item)) {
      texts.push_back(read_text(item));
    }
  }
  return texts;
}

/// Reads a JSON number as the check mask.
///
/// @param value The value, or null.
/// @return The mask. Nothing when `value` is null or is not an unsigned integer.
[[nodiscard]] std::optional<std::uint64_t> read_mask(const yyjson_val* value) {
  if (!yyjson_is_uint(value)) {
    return std::nullopt;
  }
  return yyjson_get_uint(value);
}

}  // namespace

Config parse_config(std::string_view json) {
  yyjson_doc* const document = yyjson_read(json.data(), json.size(), YYJSON_READ_NOFLAG);
  if (document == nullptr) {
    return {};
  }
  const yyjson_val* const root = yyjson_doc_get_root(document);
  Config config{
      .build_id = read_text(yyjson_obj_get(root, "build_id")),
      .checks = read_texts(yyjson_obj_get(root, "checks")),
      .checks_mask = read_mask(yyjson_obj_get(root, "m")),
      .stub_class = read_optional_text(yyjson_obj_get(root, "s")),
  };
  yyjson_doc_free(document);
  return config;
}

}  // namespace rasp
