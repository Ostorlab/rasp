/// compiled_in: the plugins compiled into the runtime.

#pragma once

#include <span>

#include "rasp/plugin.h"

namespace rasp::plugins {

/// The plugins compiled into the runtime, in the order the build was given them. The build generates this function.
///
/// @return The plugins, which live as long as the process. Empty when the runtime has no plugin.
[[nodiscard]] std::span<const Plugin* const> compiled_in();

}  // namespace rasp::plugins
