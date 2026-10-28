/// read_config: the runtime's config, which the packer writes into RaspRuntime.framework.

#pragma once

#include "rasp/config.h"

namespace rasp::ios {

/// Reads the runtime's config, the `config.json` file of RaspRuntime.framework.
///
/// @return The config. Each field is empty when the framework has no config file or it can't be read.
[[nodiscard]] Config read_config();

}  // namespace rasp::ios
