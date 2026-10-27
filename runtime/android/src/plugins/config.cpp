/// read_config: the config of a plugin, read from the app's own APK.

#include "plugins/config.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "apk/archive.h"
#include "apk/location.h"
#include "rasp/plugins/host.h"

namespace rasp::android::plugins {

namespace {

/// The folder of APK entries that hold the plugins' configs, one entry per plugin, named after it.
constexpr std::string_view kConfigFolder = "assets/rasp/plugin-config/";

}  // namespace

std::string read_config(std::string_view name) {
  const std::optional<std::string> apk = apk::self_apk_path();
  if (!apk.has_value()) {
    return {};
  }
  const std::optional<std::vector<std::uint8_t>> config =
      apk::read_stored_entry(*apk, std::string(kConfigFolder) + std::string(name), rasp::plugins::kMaxConfigSize);
  if (!config.has_value()) {
    return {};
  }
  return {config->begin(), config->end()};
}

}  // namespace rasp::android::plugins
