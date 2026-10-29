/// The app's Library directory on iOS, resolved from the HOME environment variable with a getpwuid fallback.

#include "data_dir.h"

#include <cstddef>
#include <cstdlib>
#include <optional>
#include <pwd.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace rasp::ios {

namespace {

/// The HOME environment variable or the home directory from the password database, which on iOS points to the app's
/// sandbox container, such as `/var/mobile/Containers/Data/Application/<uuid>`.
[[nodiscard]] std::optional<std::string> home_dir() {
  // NOLINTNEXTLINE(concurrency-mt-unsafe): getenv is safe here — the runtime runs before the app's own code.
  const char* home = getenv("HOME");
  if (home != nullptr && home[0] == '/') {
    return std::string(home);
  }
  const struct passwd* pw = getpwuid(getuid());
  if (pw != nullptr && pw->pw_dir != nullptr && pw->pw_dir[0] == '/') {
    return std::string(pw->pw_dir);
  }
  return std::nullopt;
}

}  // namespace

std::optional<std::string> data_dir() {
  const std::optional<std::string> home = home_dir();
  if (!home.has_value()) {
    return std::nullopt;
  }
  std::string path = *home + "/Library";
  struct stat info {};
  if (stat(path.c_str(), &info) != 0) {
    return std::nullopt;
  }
  return path;
}

}  // namespace rasp::ios
