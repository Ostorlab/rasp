/// The app's internal data directory on Android, derived from /proc/self/cmdline.

#include "data_dir.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>

#include "rasp/util/read_file.h"

namespace rasp::android {

namespace {

/// The largest /proc/self/cmdline accepted.
constexpr std::size_t kMaxCmdlineSize = 4096;

/// The package name from the command line. Android sets a process's command line to its process name, which is the
/// package name, possibly followed by a colon and the name of a private process.
[[nodiscard]] std::string_view package_of(std::string_view cmdline) {
  const std::size_t nul = cmdline.find('\0');
  const std::string_view process = cmdline.substr(0, nul == std::string_view::npos ? cmdline.size() : nul);
  const std::size_t colon = process.find(':');
  return process.substr(0, colon == std::string_view::npos ? process.size() : colon);
}

}  // namespace

std::optional<std::string> data_dir() {
  const std::optional<std::string> cmdline = rasp::util::read_file("/proc/self/cmdline", kMaxCmdlineSize);
  if (!cmdline.has_value()) {
    return std::nullopt;
  }
  const std::string_view package = package_of(*cmdline);
  if (package.empty()) {
    return std::nullopt;
  }
  std::string path = "/data/data/";
  path += package;
  path += "/files";
  struct stat info {};
  if (stat(path.c_str(), &info) != 0) {
    return std::nullopt;
  }
  return path;
}

}  // namespace rasp::android
