/// The API of the plugins compiled into the RASP runtime.

#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins {

/// A check.
///
/// @return What the check observed.
using Check = std::vector<Observation> (*)();

/// A plugin compiled into the runtime.
struct Plugin {
  /// The plugin's name.
  std::string_view name;
  /// Initialises the plugin.
  ///
  /// @param config The plugin's config, valid only during the call. Empty when it has none.
  /// @return Whether the plugin accepts the config.
  bool (*init)(std::string_view config);
  /// The plugin's checks.
  std::span<const Check> checks;
  /// Receives all the observations. May be null.
  ///
  /// @param observations All the observations, valid only during the call.
  void (*on_observations)(std::span<const Observation> observations) = nullptr;
};

}  // namespace rasp::plugins
