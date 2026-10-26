/// load_plugins: loads the plugins the packer listed in RaspRuntime.framework.

#pragma once

#include <vector>

#include "rasp/plugins/host.h"

namespace rasp::ios::plugins {

/// Loads and initialises every plugin listed in the runtime's own framework.
///
/// The list is the file `plugins.list` in RaspRuntime.framework, found from the path of the runtime's own code, and a
/// plugin's config is the file `plugin-config/<name>` next to it; a config that is absent or larger than
/// rasp::plugins::kMaxConfigSize is given as empty. A plugin is the binary `rasp_plugin_<name>` of the framework
/// `rasp_plugin_<name>.framework`, loaded through the run path, so the dynamic loader finds it in the app's
/// `Frameworks/`, the way it found RaspRuntime.framework. The plugin's rasp_host gives the platform `ios`, no Java VM,
/// and its config.
///
/// @return One entry per listed name, in list order, with the table its rasp_plugin_init returned. Empty when the
/// framework can't be found or has no plugin list.
[[nodiscard]] std::vector<rasp::plugins::Listed> load_plugins();

}  // namespace rasp::ios::plugins
