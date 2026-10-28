/// parse_config: reads the runtime's config with yyjson.

#include "rasp/parse_config.h"

#include <string>
#include <string_view>
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

}  // namespace

Config parse_config(std::string_view json) {
  yyjson_doc* const document = yyjson_read(json.data(), json.size(), YYJSON_READ_NOFLAG);
  if (document == nullptr) {
    return {};
  }
  const yyjson_val* const root = yyjson_doc_get_root(document);
  Config config{.build_id = read_text(yyjson_obj_get(root, "build_id"))};
  yyjson_doc_free(document);
  return config;
}

}  // namespace rasp
