/// read_config: the config of a plugin, read from RaspRuntime.framework.

#include "plugins/config.h"

#include <cstddef>
#include <dlfcn.h>
#include <optional>
#include <string>
#include <string_view>

#include "rasp/plugins/host.h"
#include "rasp/util/read_file.h"

namespace rasp::ios::plugins {

namespace {

/// The folder of RaspRuntime.framework that holds the plugins' configs, one file per plugin, named after it.
constexpr std::string_view kConfigFolder = "plugin-config";

/// The folder of RaspRuntime.framework, from the path the dynamic loader records for the runtime's own image.
///
/// @return The folder, or nothing when the dynamic loader doesn't know the image or its path has no folder.
[[nodiscard]] std::optional<std::string> framework_folder() {
  Dl_info info{};
  if (dladdr(&kConfigFolder, &info) == 0 || info.dli_fname == nullptr) {
    return std::nullopt;
  }
  const std::string_view path(info.dli_fname);
  const std::size_t slash = path.find_last_of('/');
  if (slash == std::string_view::npos || slash == 0) {
    return std::nullopt;
  }
  return std::string(path.substr(0, slash));
}

}  // namespace

std::string read_config(std::string_view name) {
  const std::optional<std::string> folder = framework_folder();
  if (!folder.has_value()) {
    return {};
  }
  const std::string path = *folder + "/" + std::string(kConfigFolder) + "/" + std::string(name);
  return rasp::util::read_file(path, rasp::plugins::kMaxConfigSize).value_or("");
}

}  // namespace rasp::ios::plugins
