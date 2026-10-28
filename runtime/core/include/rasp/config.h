/// Config: the runtime's config, which the packer writes into the protected app.

#pragma once

#include <string>

namespace rasp {

/// The runtime's config, which the packer writes into the protected app. Each field is empty when the runtime can't
/// read the config.
struct Config {
  /// The id of the protected build.
  std::string build_id;
};

}  // namespace rasp
