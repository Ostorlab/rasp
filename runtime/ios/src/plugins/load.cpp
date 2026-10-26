/// load_plugins: reads the plugin list and configs from RaspRuntime.framework and loads each plugin framework.

#include "plugins/load.h"

#include <cstddef>
#include <dlfcn.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/plugin.h"
#include "rasp/plugins/host.h"
#include "rasp/plugins/loader.h"
#include "rasp/util/read_file.h"

namespace rasp::ios::plugins {

namespace {

/// The file of RaspRuntime.framework that lists the plugins, one name per line.
constexpr std::string_view kListFile = "plugins.list";
/// The folder of RaspRuntime.framework that holds the plugins' configs, one file per plugin, named after it.
constexpr std::string_view kConfigFolder = "plugin-config";
/// What a plugin's framework and binary names start with, before the plugin's name.
constexpr std::string_view kPluginPrefix = "rasp_plugin_";
/// The platform name the plugins see.
constexpr std::string_view kPlatform = "ios";

/// The folder of RaspRuntime.framework, from the path the dynamic loader records for the runtime's own image.
///
/// @return The folder, or nothing when the dynamic loader doesn't know the image or its path has no folder.
[[nodiscard]] std::optional<std::string> framework_folder() {
  Dl_info info{};
  if (dladdr(&kListFile, &info) == 0 || info.dli_fname == nullptr) {
    return std::nullopt;
  }
  const std::string_view path(info.dli_fname);
  const std::size_t slash = path.find_last_of('/');
  if (slash == std::string_view::npos || slash == 0) {
    return std::nullopt;
  }
  return std::string(path.substr(0, slash));
}

/// The path the dynamic loader loads for the plugin `name`.
///
/// @param name A valid plugin name.
/// @return The binary `rasp_plugin_<name>` of `rasp_plugin_<name>.framework`, under the run path.
[[nodiscard]] std::string library_path(std::string_view name) {
  const std::string binary = std::string(kPluginPrefix) + std::string(name);
  return "@rpath/" + binary + ".framework/" + binary;
}

}  // namespace

std::vector<rasp::plugins::Listed> load_plugins() {
  std::vector<rasp::plugins::Listed> listed;
  const std::optional<std::string> folder = framework_folder();
  if (!folder.has_value()) {
    return listed;
  }
  const std::optional<std::string> list =
      rasp::util::read_file(*folder + "/" + std::string(kListFile), rasp::plugins::kMaxListSize);
  if (!list.has_value()) {
    return listed;
  }
  for (std::string& name : rasp::plugins::parse_list(*list)) {
    const rasp_plugin* table = nullptr;
    if (rasp::plugins::valid_name(name)) {
      const std::string config =
          rasp::util::read_file(*folder + "/" + std::string(kConfigFolder) + "/" + name, rasp::plugins::kMaxConfigSize)
              .value_or("");
      table = rasp::plugins::load_plugin(library_path(name), rasp::plugins::host_info(kPlatform, config, nullptr));
    }
    listed.push_back({.name = std::move(name), .table = table});
  }
  return listed;
}

}  // namespace rasp::ios::plugins
