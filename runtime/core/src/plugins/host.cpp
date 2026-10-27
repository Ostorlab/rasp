/// Host: runs the plugins' checks, then gives the plugins the observations.

#include "rasp/plugins/host.h"

#include <algorithm>
#include <iterator>
#include <span>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins {

Host::Host(std::span<const Plugin* const> plugins) : plugins_(plugins) {}

std::vector<Observation> Host::run(std::vector<Observation> observations) const {
  for (const Plugin* const plugin : plugins_) {
    for (const Check check : plugin->checks) {
      std::ranges::move(check(), std::back_inserter(observations));
    }
  }
  for (const Plugin* const plugin : plugins_) {
    if (plugin->on_observations != nullptr) {
      plugin->on_observations(observations);
    }
  }
  return observations;
}

}  // namespace rasp::plugins
