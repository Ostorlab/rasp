/// load_plugin: loads one plugin library with the dynamic loader and initialises it.

#pragma once

#include <string>

#include "rasp/plugin.h"

namespace rasp::plugins {

/// Loads the plugin library at `path` and calls its rasp_plugin_init with `host`.
///
/// The library is loaded with `dlopen`, its symbols resolved at once and kept local to it. It is never unloaded, even
/// when it turns out not to be a plugin or declines, because its own code may already be running.
///
/// @param path What `dlopen` loads: a file name, which the platform's library search finds, or a path.
/// @param host What the runtime tells the plugin. It is valid only during the call.
/// @return The table rasp_plugin_init returned, still unchecked. Null when the library can't be loaded, exports no
/// rasp_plugin_init, or returned null.
[[nodiscard]] const rasp_plugin* load_plugin(const std::string& path, const rasp_host& host);

}  // namespace rasp::plugins
