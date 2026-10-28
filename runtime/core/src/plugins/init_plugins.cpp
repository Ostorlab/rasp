/// init_plugins: calls the init of every plugin.

#include <span>

#include "rasp/config.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"

namespace rasp::plugins {

void init_plugins(std::span<const Plugin* const> plugins, const Config& config) {
  for (const Plugin* const plugin : plugins) {
    plugin->init(config);
  }
}

}  // namespace rasp::plugins
