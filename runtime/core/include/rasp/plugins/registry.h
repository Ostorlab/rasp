/// The plugins compiled into the runtime: compiled_in, which returns them, init_plugins, which initialises them, and
/// run_plugins, which runs them.

#pragma once

#include <span>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
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
/// @param context The values the plugins share, which each plugin's `init` receives. It must live as long as the
/// process.
void init_plugins(std::span<const Plugin* const> plugins, const Config& config, Context& context);

/// Runs the plugins after the built-in checks.
///
/// It runs every check of every plugin, in order, and adds what each check returns after the built-in observations.
/// Then it gives each plugin that has an `on_observations` all the observations, in the order of `plugins`: the
/// built-in ones and those of the plugins' checks.
///
/// Direct callers have no monitor metadata. Dispatch is serialized on Context and clears any cycle key.
/// Monitor-run on_observations callbacks receive only bounded retained observations; oversized observations
/// are dropped whole. Their span carries no drop/coverage accounting. Prefer Plugin::on_cycle and retain its
/// owning snapshot from rasp/cycle.h for observations together with completeness/drop metadata.
/// @param plugins The plugins, in the order their checks run.
/// @param observations The observations of the built-in checks.
/// @param context The values the plugins share, which every check and `on_observations` receives. It must be the one
/// `init_plugins` gave the plugins.
/// @return The built-in observations, then those of the plugins' checks.
[[nodiscard]] std::vector<Observation> run_plugins(std::span<const Plugin* const> plugins,
                                                   std::vector<Observation> observations, Context& context);

}  // namespace rasp::plugins
