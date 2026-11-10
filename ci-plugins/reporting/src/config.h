/// Config: where the reporting plugin posts the requests, and the build id and install id every request holds.

#pragma once

#include <optional>
#include <string>

namespace rasp::plugins::reporting {

/// Where the plugin posts the requests, and the build id and install id every request holds.
struct Config {
  /// The URL the requests are posted to. It starts with `http://` or `https://`. The build compiles it in.
  std::string endpoint;
  /// The id of the protected build, which the runtime gives the plugin's init.
  std::string build_id;
  /// The id of this install of the app, which the runtime gives the plugin's init. `std::nullopt` when the runtime
  /// has none.
  std::optional<std::string> install_id = std::nullopt;
};

}  // namespace rasp::plugins::reporting
