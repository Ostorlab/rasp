/// Config: the runtime's config, which the packer writes into the protected app, and is_check_enabled, which reads it.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/local_policy.h"

namespace rasp {

/// The runtime's config, which the packer writes into the protected app. Each field is empty when the runtime can't
/// read the config.
struct Config {
  /// The id of the protected build.
  std::string build_id;
  /// The ids of the check groups the protected app runs. `std::nullopt` when the runtime can't read a list: then no
  /// group runs, as with an empty list.
  std::optional<std::vector<std::string>> checks = std::nullopt;
  /// The id of this install of the app, a random UUID such as `0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b`, which the runtime
  /// creates on the first launch and keeps in the app's own storage (`install_id.h`). `std::nullopt` when the runtime
  /// can't read or keep it. The packer does not write it.
  std::optional<std::string> install_id = std::nullopt;
  /// Explicit host-called policy; absence retains report-only behavior.
  LocalPolicy local_policy{};
};

/// Whether the protected app runs a check group.
///
/// @param config The runtime's config.
/// @param group The group's id, the name of its function in `checks::`, for example `debugger`.
/// @return `true` when the config's list has this group. Without a list, no group runs.
[[nodiscard]] bool is_check_enabled(const Config& config, std::string_view group);

}  // namespace rasp
