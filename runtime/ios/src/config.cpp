/// read_config: finds config.json in RaspRuntime.framework through CFBundle, and reads it.

#include "config.h"

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFBundle.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFURL.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "rasp/config.h"
#include "rasp/parse_config.h"
#include "rasp/util/read_file.h"

namespace rasp::ios {

namespace {

/// The largest config file the runtime reads, in bytes.
constexpr std::size_t kMaxConfigSize = std::size_t{64} * 1024;

/// The longest path of the config file, in bytes, with its terminating null.
constexpr std::size_t kMaxPathSize = 1024;

/// Finds the config file in the framework's bundle.
///
/// @return The file's path. Nothing when the framework's bundle or its config file can't be found.
[[nodiscard]] std::optional<std::string> config_path() {
  CFBundleRef bundle = CFBundleGetBundleWithIdentifier(CFSTR(RASP_FRAMEWORK_IDENTIFIER));
  if (bundle == nullptr) {
    return std::nullopt;
  }
  const CFURLRef url = CFBundleCopyResourceURL(bundle, CFSTR("config"), CFSTR("json"), nullptr);
  if (url == nullptr) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kMaxPathSize> path{};
  const bool found = CFURLGetFileSystemRepresentation(url, 1U, path.data(), static_cast<CFIndex>(path.size())) != 0U;
  CFRelease(url);
  if (!found) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): CFURLGetFileSystemRepresentation writes a C string.
  return std::string(reinterpret_cast<const char*>(path.data()));
}

}  // namespace

Config read_config() {
  const std::optional<std::string> path = config_path();
  if (!path.has_value()) {
    return {};
  }
  const std::optional<std::string> json = rasp::util::read_file(*path, kMaxConfigSize);
  if (!json.has_value()) {
    return {};
  }
  return parse_config(*json);
}

}  // namespace rasp::ios
