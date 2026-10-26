/// The Android app-identity self-check: the package-name probe over the process's command line, the user-id probe over
/// the process's own uid, and their unsupported results off Android.

#include "checks/identity.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef __ANDROID__
#include <unistd.h>
#endif

#include "rasp/observation.h"
#include "util/read_file.h"

namespace rasp::android::checks {

namespace {

/// The signal of the package-name probe.
constexpr std::string_view kPackageSignal = "id.package";
/// The source of the package-name probe read at load time, from the process's command line.
constexpr std::string_view kPackageSource = "proc_cmdline";

/// The signal of the user-id probe.
constexpr std::string_view kUidSignal = "id.uid";
/// The source of the user-id probe, the process's own uid.
constexpr std::string_view kUidSource = "getuid";

#ifdef __ANDROID__
/// The process's command line, whose first NUL-separated argument is the package name. Only identity() reads it, on a
/// device, so it is guarded; observe_package takes the path from its caller.
constexpr std::string_view kCmdlinePath = "/proc/self/cmdline";
#endif

/// The largest command line read. A real one is well under this.
constexpr std::size_t kMaxCmdlineSize = std::size_t{64} << 10U;

/// The package name in `cmdline`, the process's command line. Android sets the command line to the process name, whose
/// first NUL-separated field is the package, optionally followed by a private `:<name>` suffix for a process an app
/// declares with a private `android:process` (such as `com.example:remote`). Taking the part before that colon gives
/// the same package for every private process of a multi-process app. A global `android:process` name (such as
/// `com.other:remote`) has a different process name before the colon, not the package, so for those this read isn't the
/// package; observe_package reports whatever the command line holds and the server weighs it. The view is empty when
/// there is no name.
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

Observation observe_uid(std::int64_t uid) { return observed(kUidSignal, kUidSource, uid); }

std::vector<Observation> identity() {
#ifdef __ANDROID__
  return {observe_package(kCmdlinePath), observe_uid(static_cast<std::int64_t>(getuid()))};
#else
  return {unsupported(kPackageSignal, kPackageSource), unsupported(kUidSignal, kUidSource)};
#endif
}

}  // namespace rasp::android::checks
