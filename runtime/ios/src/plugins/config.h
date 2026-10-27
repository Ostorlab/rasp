/// read_config: reads the config of a plugin compiled into the runtime from RaspRuntime.framework.

#pragma once

#include <string>
#include <string_view>

namespace rasp::ios::plugins {

/// Reads the config of the plugin `name` from the runtime's own framework.
///
/// The config is the file `plugin-config/<name>` in RaspRuntime.framework, as the packer writes it. The framework is
/// found from the path of the runtime's own code.
///
/// @param name The plugin's name.
/// @return The config. Empty when the framework can't be found, or when the file is absent, can't be read or is larger
/// than rasp::plugins::kMaxConfigSize.
[[nodiscard]] std::string read_config(std::string_view name);

}  // namespace rasp::ios::plugins
