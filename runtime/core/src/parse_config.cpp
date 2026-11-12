/// parse_config: reads the runtime's config with yyjson.

#include "rasp/parse_config.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <yyjson.h>

#include "local_policy_config.h"
#include "rasp/config.h"
#include "rasp/local_policy.h"

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

}  // namespace

Config parse_config(std::string_view json) {
  Config invalid;
  invalid.local_policy.state = LocalPolicyStateKind::kInvalid;
  if (!policy_internal::config_envelope(json)) {
    return invalid;
  }
  std::vector<std::byte> pool(131072);
  yyjson_alc allocator{};
  if (!yyjson_alc_pool_init(&allocator, pool.data(), pool.size())) {
    return invalid;
  }
  std::string input(json);
  yyjson_doc* const document = yyjson_read_opts(input.data(), json.size(), YYJSON_READ_NOFLAG, &allocator, nullptr);
  if (document == nullptr) {
    return invalid;
  }
  const yyjson_val* const root = yyjson_doc_get_root(document);
  if (!yyjson_is_obj(root)) {
    yyjson_doc_free(document);
    return invalid;
  }
  Config config{
      .build_id = read_text(yyjson_obj_get(root, "build_id")),
      .checks = read_texts(yyjson_obj_get(root, "checks")),
  };
  policy_internal::read_policy(root, config);
  yyjson_doc_free(document);
  return config;
}

}  // namespace rasp
