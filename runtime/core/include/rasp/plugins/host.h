/// Host, which runs the plugins compiled into the runtime with the built-in checks.

#pragma once

#include <span>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins {

/// The plugins compiled into the runtime: runs their checks after the built-in checks, and gives them all the
/// observations.
class Host {
 public:
  /// Keeps the plugins.
  ///
  /// @param plugins The plugins, in the order their checks run. They must outlive the host.
  explicit Host(std::span<const Plugin* const> plugins);

  /// Runs the plugins after the built-in checks.
  ///
  /// It runs every check of every plugin, in order. Then it gives each plugin that has an `on_observations` all the
  /// observations: the built-in ones and those of every plugin's checks.
  ///
  /// @param observations The observations of the built-in checks.
  /// @return The built-in observations, then those of the plugins' checks.
  [[nodiscard]] std::vector<Observation> run(std::vector<Observation> observations) const;

 private:
  /// The plugins, in order.
  std::span<const Plugin* const> plugins_;
};

}  // namespace rasp::plugins
