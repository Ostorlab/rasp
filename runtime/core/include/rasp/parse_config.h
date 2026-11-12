/// parse_config: reads the runtime's config from the JSON the packer writes.

#pragma once

#include <string_view>

#include "rasp/config.h"

namespace rasp {

/// Reads the runtime's config from the JSON the packer writes: an object with a `build_id` string and a `checks` array
/// of check group ids. Members the runtime doesn't know are ignored.
///
/// @param json The JSON text.
/// @return The config. A field is empty when the text is not a JSON object, or the object's member for it is missing or
/// is not of its type: a string for `build_id`, an array for `checks`. The items of `checks` that are not strings are
/// ignored.
[[nodiscard]] Config parse_config(std::string_view json);

}  // namespace rasp
