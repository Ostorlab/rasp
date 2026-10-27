/// read_config: reads the config of a plugin compiled into the runtime from the app's own APK.

#pragma once

#include <string>
#include <string_view>

namespace rasp::android::plugins {

/// Reads the config of the plugin `name` from the app's own APK.
///
/// The config is the APK entry `assets/rasp/plugin-config/<name>`, stored uncompressed, as the packer writes it.
///
/// @param name The plugin's name.
/// @return The config. Empty when the APK can't be found, or when the entry is absent, compressed or larger than
/// rasp::plugins::kMaxConfigSize.
[[nodiscard]] std::string read_config(std::string_view name);

}  // namespace rasp::android::plugins
