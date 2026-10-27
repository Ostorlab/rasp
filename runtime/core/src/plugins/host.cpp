/// Host: initialises the plugins with their configs, then runs their checks and gives them the observations.

#include "rasp/plugins/host.h"

#include <algorithm>
#include <iterator>
#include <span>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins {

Host::Host(std::span<const Plugin* const> plugins, ConfigReader read_config) {
  load_observations_.reserve(plugins.size());
  for (const Plugin* const plugin : plugins) {
    const std::string config = read_config(plugin->name);
    if (plugin->init(config)) {
      load_observations_.push_back(observed(kLoadSignal, plugin->name, Value{}));
      accepted_.push_back(plugin);
    } else {
      load_observations_.push_back(failed(kLoadSignal, plugin->name));
    }
  }
}

std::vector<Observation> Host::run(std::vector<Observation> observations) const {
  observations.insert(observations.end(), load_observations_.begin(), load_observations_.end());
  for (const Plugin* const plugin : accepted_) {
    for (const Check check : plugin->checks) {
      std::ranges::move(check(), std::back_inserter(observations));
    }
  }
  for (const Plugin* const plugin : accepted_) {
    if (plugin->on_observations != nullptr) {
      plugin->on_observations(observations);
    }
  }
  return observations;
}

}  // namespace rasp::plugins
