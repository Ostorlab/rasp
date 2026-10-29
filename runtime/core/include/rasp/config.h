/// Config: the runtime's config, which the packer writes into the protected app, and the install id the runtime
/// generates on first launch.

#pragma once

#include <string>

#include "rasp/install_id.h"

namespace rasp {

/// The runtime's config. The packer writes `build_id` into the protected app; the runtime generates `install_id` on
/// first launch and reloads it on every subsequent launch.
struct Config {
  /// The id of the protected build. Empty when the runtime can't read the config.
  std::string build_id;
  /// The installation id of this device, or zeroed when it could not be read or generated.
  InstallId install_id{};
};

}  // namespace rasp
