/// Config: the runtime's config, which the packer writes into the protected app, and is_check_enabled, which reads it.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rasp {

/// The runtime's config, which the packer writes into the protected app. Each field is empty when the runtime can't
/// read the config.
struct Config {
  /// The id of the protected build.
  std::string build_id;
  /// The ids of the check groups the protected app runs. `std::nullopt` when the runtime can't read a list: then no
  /// group runs, as with an empty list.
  std::optional<std::vector<std::string>> checks = std::nullopt;
};

/// Whether the protected app runs a check group.
///
/// @param config The runtime's config.
/// @param group The group's id, the name of its function in `checks::`, for example `debugger`.
/// @return `true` when the config's list has this group. Without a list, no group runs.
[[nodiscard]] bool is_check_enabled(const Config& config, std::string_view group);

}  // namespace rasp
