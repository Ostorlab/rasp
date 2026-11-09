/// Config: the runtime's config, which the packer writes into the protected app, and is_check_enabled, which reads it.

#pragma once

#include <cstdint>
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
  /// The ids of the check groups the protected app runs, as the config's list names them. `std::nullopt` when the
  /// runtime can't read a list: then the groups come from `checks_mask`, and without either no group runs.
  std::optional<std::vector<std::string>> checks = std::nullopt;
  /// The ids of the check groups the protected app runs, as the config's mask carries them: one bit per group, in
  /// the order the platform's monitoring runs them. `std::nullopt` when the runtime can't read a mask: then the
  /// groups come from `checks`.
  std::optional<std::uint64_t> checks_mask = std::nullopt;
  /// The id of this install of the app, a random UUID such as `0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b`, which the runtime
  /// creates on the first launch and keeps in the app's own storage (`install_id.h`). `std::nullopt` when the runtime
  /// can't read or keep it. The packer does not write it.
  std::optional<std::string> install_id = std::nullopt;
};

/// Whether the protected app runs a check group.
///
/// @param config The runtime's config.
/// @param group The group's id, the name of its function in `checks::`, for example `debugger`.
/// @return `true` when the config's list has this group. Without a list, no group runs.
[[nodiscard]] bool is_check_enabled(const Config& config, std::string_view group);

}  // namespace rasp
