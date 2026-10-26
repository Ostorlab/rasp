/// load_plugins: loads the plugins the packer listed in the app's APK.

#pragma once

#include <vector>

#include "rasp/plugins/host.h"

namespace rasp::android::plugins {

/// Loads and initialises every plugin listed in the app's own APK.
///
/// The list is the APK entry `assets/rasp/plugins.list`, and a plugin's config is the entry
/// `assets/rasp/plugin-config/<name>`, both stored uncompressed; a config that is absent or larger than
/// rasp::plugins::kMaxConfigSize is given as empty. A plugin is the library `librasp_plugin_<name>.so`, loaded by file
/// name, so the dynamic linker finds it in the app's native libraries, the way it found librasp.so. The plugin's
/// rasp_host gives the platform `android`, the process's Java VM and its config.
///
/// @return One entry per listed name, in list order, with the table its rasp_plugin_init returned. Empty when the APK
/// can't be found or has no plugin list.
[[nodiscard]] std::vector<rasp::plugins::Listed> load_plugins();

}  // namespace rasp::android::plugins
