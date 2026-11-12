/// Internal common dispatch used by legacy callers and actual finite monitor runs.
#pragma once
#include <span>
#include <vector>

#include "cycle_internal.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
namespace rasp::plugins {
/// Dispatches checks and callbacks while the caller holds the Context dispatch guard.
/// @param plugins Existing ordered plugins.
/// @param observations Builtin output, replaced with bounded retained output for monitor runs.
/// @param context Serialized process values.
/// @param cycle Non-null only for actual monitor runs; takes ownership before callbacks.
/// @return All legacy observations; monitor observations live in cycle.snapshot instead.
[[nodiscard]] std::vector<Observation> dispatch_plugins(std::span<const Plugin* const> plugins,
                                                        std::vector<Observation> observations, Context& context,
                                                        CycleDispatch* cycle = nullptr);
}  // namespace rasp::plugins
