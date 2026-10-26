/// load_plugins: reads the plugin list and configs from the app's APK and loads each plugin library.

#include "plugins/load.h"

#include <cstddef>
#include <cstdint>
#include <jni.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "apk/archive.h"
#include "apk/location.h"
#include "rasp/plugin.h"
#include "rasp/plugins/host.h"
#include "rasp/plugins/loader.h"

namespace rasp::android::plugins {

namespace {

/// The APK entry that lists the plugins, one name per line.
constexpr std::string_view kListEntry = "assets/rasp/plugins.list";
/// The folder of APK entries that hold the plugins' configs, one entry per plugin, named after it.
constexpr std::string_view kConfigFolder = "assets/rasp/plugin-config/";
/// What a plugin library's file name starts with, before the plugin's name.
constexpr std::string_view kLibraryPrefix = "librasp_plugin_";
/// What a plugin library's file name ends with, after the plugin's name.
constexpr std::string_view kLibrarySuffix = ".so";
/// The platform name the plugins see.
constexpr std::string_view kPlatform = "android";

/// The process's Java VM.
///
/// @return The `JavaVM*`, or null when the process runs none.
[[nodiscard]] void* java_vm() {
  JavaVM* vm = nullptr;
  jsize count = 0;
  if (JNI_GetCreatedJavaVMs(&vm, 1, &count) != JNI_OK || count < 1) {
    return nullptr;
  }
  return vm;
}

/// Reads one stored entry of the APK as bytes in a string.
///
/// @param apk The APK to read.
/// @param name The entry's full name.
/// @param limit The largest entry accepted, in bytes.
/// @return The entry's bytes. Nothing when the entry can't be read, is compressed or is larger than `limit`.
[[nodiscard]] std::optional<std::string> read_entry(const std::string& apk, std::string_view name, std::size_t limit) {
  const std::optional<std::vector<std::uint8_t>> bytes = apk::read_stored_entry(apk, name, limit);
  if (!bytes.has_value()) {
    return std::nullopt;
  }
  return std::string(bytes->begin(), bytes->end());
}

}  // namespace

std::vector<rasp::plugins::Listed> load_plugins() {
  std::vector<rasp::plugins::Listed> listed;
  const std::optional<std::string> apk = apk::self_apk_path();
  if (!apk.has_value()) {
    return listed;
  }
  const std::optional<std::string> list = read_entry(*apk, kListEntry, rasp::plugins::kMaxListSize);
  if (!list.has_value()) {
    return listed;
  }
  void* const vm = java_vm();
  for (std::string& name : rasp::plugins::parse_list(*list)) {
    const rasp_plugin* table = nullptr;
    if (rasp::plugins::valid_name(name)) {
      const std::string config =
          read_entry(*apk, std::string(kConfigFolder) + name, rasp::plugins::kMaxConfigSize).value_or("");
      const std::string library = std::string(kLibraryPrefix) + name + std::string(kLibrarySuffix);
      table = rasp::plugins::load_plugin(library, rasp::plugins::host_info(kPlatform, config, vm));
    }
    listed.push_back({.name = std::move(name), .table = table});
  }
  return listed;
}

}  // namespace rasp::android::plugins
