/// The plugins compiled into the runtime: compiled_in, which returns them, init_plugins, which initialises them, and
/// run_plugins, which runs them.

#pragma once

#include <span>
#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins {

/// The plugins compiled into the runtime, in the order the build was given them. The build generates this function.
///
/// @return The plugins, which live as long as the process. Empty when the runtime has no plugin.
[[nodiscard]] std::span<const Plugin* const> compiled_in();

/// Initialises the plugins: calls the `init` of each plugin, in the order of `plugins`.
///
/// @param plugins The plugins.
/// @param config The runtime's config, which each plugin's `init` receives.
void init_plugins(std::span<const Plugin* const> plugins, const Config& config);

/// Runs the plugins after the built-in checks.
///
/// It runs every check of every plugin, in order, and adds what each check returns after the built-in observations.
/// Then it gives each plugin that has an `on_observations` all the observations, in the order of `plugins`: the
/// built-in ones and those of the plugins' checks.
///
/// @param plugins The plugins, in the order their checks run.
/// @param observations The observations of the built-in checks.
/// @return The built-in observations, then those of the plugins' checks.
[[nodiscard]] std::vector<Observation> run_plugins(std::span<const Plugin* const> plugins,
                                                   std::vector<Observation> observations);

}  // namespace rasp::plugins
