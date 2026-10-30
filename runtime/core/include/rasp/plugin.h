/// The API of the plugins compiled into the RASP runtime.

#pragma once

#include <span>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"

namespace rasp::plugins {

/// A check.
///
/// @param context The values the plugins share, the same in every call. It lives as long as the process.
/// @return What the check observed.
using Check = std::vector<Observation> (*)(Context& context);

/// A plugin compiled into the runtime.
struct Plugin {
  /// Initialises the plugin. The runtime calls it once, when it starts, before the plugin's checks and its
  /// `on_observations`.
  ///
  /// @param config The runtime's config, valid only during the call.
  /// @param context The values the plugins share, the same in every call. It lives as long as the process.
  void (*init)(const Config& config, Context& context);
  /// The plugin's checks.
  std::span<const Check> checks;
  /// Receives all the observations. May be null.
  ///
  /// @param observations All the observations, valid only during the call.
  /// @param context The values the plugins share, the same in every call. It lives as long as the process.
  void (*on_observations)(std::span<const Observation> observations, Context& context) = nullptr;
};

}  // namespace rasp::plugins
