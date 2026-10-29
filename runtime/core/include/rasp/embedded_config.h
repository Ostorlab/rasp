/// read_embedded_config: the runtime's config, which the packer writes into the runtime's own binary.

#pragma once

#include <cstddef>

#include "rasp/config.h"

namespace rasp {

/// The size of the space the runtime's binary keeps for its config, in bytes. The packer writes the config's JSON at
/// its start, followed by zero bytes to its end. The space is the section `.rasp_config` of librasp.so, and the section
/// `__rasp_config` of the `__DATA` segment of RaspRuntime.framework's binary.
inline constexpr std::size_t kEmbeddedConfigSize = 4096;

/// Reads the runtime's config from the runtime's own binary, where the packer writes it.
///
/// @return The config. Each field is empty when the packer wrote no config, or the config can't be read.
[[nodiscard]] Config read_embedded_config();

}  // namespace rasp
