/// The API of the plugins compiled into the RASP runtime.

#pragma once

#include <span>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins {

/// A check.
///
/// @return What the check observed.
using Check = std::vector<Observation> (*)();

/// A plugin compiled into the runtime.
struct Plugin {
  /// The plugin's checks.
  std::span<const Check> checks;
  /// Receives all the observations. May be null.
  ///
  /// @param observations All the observations, valid only during the call.
  void (*on_observations)(std::span<const Observation> observations) = nullptr;
};

}  // namespace rasp::plugins
