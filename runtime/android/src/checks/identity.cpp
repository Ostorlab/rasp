/// The Android app-identity self-check: the package-name probe over the process's command line, and its unsupported
/// result off Android.

#include "checks/identity.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "util/read_file.h"

namespace rasp::android::checks {

namespace {

#ifdef __ANDROID__
/// Whether this build runs on Android, the only place the probe means anything.
constexpr bool kOnAndroid = true;
#else
/// Whether this build runs on Android, the only place the probe means anything.
constexpr bool kOnAndroid = false;
#endif

/// The signal of the package-name probe.
constexpr std::string_view kPackageSignal = "id.package";
/// The source of the package-name probe read at load time, from the process's command line.
constexpr std::string_view kPackageSource = "proc_cmdline";

/// The process's command line, whose first NUL-separated argument is the package name.
constexpr std::string_view kCmdlinePath = "/proc/self/cmdline";
/// The largest command line read. A real one is well under this.
constexpr std::size_t kMaxCmdlineSize = std::size_t{64} << 10U;

/// The package name in `cmdline`, the process's command line. Android sets the command line to the process name, whose
/// first NUL-separated field is the package, optionally followed by `:<name>` for a process an app declares with
/// `android:process` (such as `com.example:remote`). The package is the part before that colon, so every process of a
/// multi-process app reports the same package. The view is empty when there is no name.
[[nodiscard]] std::string_view package_name(std::string_view cmdline) {
  const std::size_t nul = cmdline.find('\0');
  const std::string_view process = cmdline.substr(0, nul == std::string_view::npos ? cmdline.size() : nul);
  const std::size_t colon = process.find(':');
  return process.substr(0, colon == std::string_view::npos ? process.size() : colon);
}

}  // namespace

Observation observe_package(std::string_view cmdline_path) {
  const std::optional<std::string> cmdline = util::read_file(cmdline_path, kMaxCmdlineSize);
  if (!cmdline) {
    return failed(kPackageSignal, kPackageSource);
  }
  const std::string_view package = package_name(*cmdline);
  if (package.empty()) {
    return failed(kPackageSignal, kPackageSource);
  }
  return observed(kPackageSignal, kPackageSource, std::string(package));
}

std::vector<Observation> identity() {
  if (!kOnAndroid) {
    return {unsupported(kPackageSignal, kPackageSource)};
  }
  return {observe_package(kCmdlinePath)};
}

}  // namespace rasp::android::checks
