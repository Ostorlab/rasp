/// The app's own storage on Android: its package name, read from the process's command line, and the `no_backup`
/// folder of its private storage.

#include "util/app_storage.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#include "rasp/util/read_file.h"

namespace rasp::android::util {

namespace {

/// The process's command line, whose first NUL-separated argument is the package name.
constexpr std::string_view kCmdlinePath = "/proc/self/cmdline";

/// The largest command line read. A real one is well under this.
constexpr std::size_t kMaxCmdlineSize = std::size_t{64} << 10U;

/// How many uids each Android user has: the user of a uid is `uid / kUidsPerUser`.
constexpr std::uint32_t kUidsPerUser = 100000;

/// The permissions of a folder the runtime creates: only the app can read, write and enter it.
constexpr mode_t kPrivateDirectoryMode = 0700;

}  // namespace

std::string_view package_name(std::string_view cmdline) {
  const std::size_t nul = cmdline.find('\0');
  const std::string_view process = cmdline.substr(0, nul == std::string_view::npos ? cmdline.size() : nul);
  const std::size_t colon = process.find(':');
  return process.substr(0, colon == std::string_view::npos ? process.size() : colon);
}

std::string no_backup_directory(std::string_view package, std::uint32_t uid) {
  std::string path = "/data/user/" + std::to_string(uid / kUidsPerUser) + "/";
  path.append(package);
  path.append("/no_backup");
  return path;
}

std::optional<std::string> make_no_backup_directory() {
  const std::optional<std::string> cmdline = rasp::util::read_file(kCmdlinePath, kMaxCmdlineSize);
  if (!cmdline) {
    return std::nullopt;
  }
  const std::string_view package = package_name(*cmdline);
  if (package.empty()) {
    return std::nullopt;
  }
  std::string directory = no_backup_directory(package, getuid());
  if (mkdir(directory.c_str(), kPrivateDirectoryMode) != 0 && errno != EEXIST) {
    return std::nullopt;
  }
  return directory;
}

}  // namespace rasp::android::util
