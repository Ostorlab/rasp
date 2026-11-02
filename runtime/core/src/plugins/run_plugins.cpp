/// run_plugins: runs the plugins' checks, then gives the plugins the observations.

#include <algorithm>
#include <iterator>
#include <span>
#include <vector>

#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"

namespace rasp::plugins {

std::vector<Observation> run_plugins(std::span<const Plugin* const> plugins, std::vector<Observation> observations,
                                     Context& context) {
  for (const Plugin* const plugin : plugins) {
    for (const Check check : plugin->checks) {
      std::ranges::move(check(context), std::back_inserter(observations));
    }
  }
  for (const Plugin* const plugin : plugins) {
    if (plugin->on_observations != nullptr) {
      plugin->on_observations(observations, context);
    }
  }
  return observations;
}

}  // namespace rasp::plugins
