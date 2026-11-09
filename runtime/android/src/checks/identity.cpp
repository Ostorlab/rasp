/// The Android app-identity self-check: the package-name probe over the process's command line, the user-id probe over
/// the process's own uid, the code-path probe over the runtime's own library load path, and their unsupported results
/// off Android.

#include "checks/identity.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef __ANDROID__
#include <array>
#include <unistd.h>

#include "apk/location.h"
#endif

#include "rasp/observation.h"
#include "rasp/util/read_file.h"
#include "util/app_storage.h"

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

/// The signal of the code-path probe.
constexpr std::string_view kCodePathSignal = "id.code_path";
/// The source of the code-path probe, the load path of the runtime's own library.
constexpr std::string_view kCodePathSource = "dladdr";

#ifdef __ANDROID__
/// The process's command line, whose first NUL-separated argument is the package name. Only identity() reads it, on a
/// device, so it is guarded; observe_package takes the path from its caller.
constexpr std::string_view kCmdlinePath = "/proc/self/cmdline";
#endif

/// The largest command line read. A real one is well under this.
constexpr std::size_t kMaxCmdlineSize = std::size_t{64} << 10U;

}  // namespace

Observation observe_package(std::string_view cmdline_path) {
  const std::optional<std::string> cmdline = rasp::util::read_file(cmdline_path, kMaxCmdlineSize);
  if (!cmdline) {
    return failed(kPackageSignal, kPackageSource);
  }
  const std::string_view package = util::package_name(*cmdline);
  if (package.empty()) {
    return failed(kPackageSignal, kPackageSource);
  }
  return observed(kPackageSignal, kPackageSource, std::string(package));
}

Observation observe_uid(std::int64_t uid) { return observed(kUidSignal, kUidSource, uid); }

Observation observe_code_path(std::string_view code_path) {
  if (code_path.empty()) {
    return failed(kCodePathSignal, kCodePathSource);
  }
  return observed(kCodePathSignal, kCodePathSource, std::string(code_path));
}

std::vector<Observation> identity() {
#ifdef __ANDROID__
  const std::optional<std::string> code_path = apk::self_library_path();
  return {
      observe_package(kCmdlinePath),
      observe_uid(static_cast<std::int64_t>(getuid())),
      observe_code_path(code_path.value_or(std::string())),
  };
#else
  return {
      unsupported(kPackageSignal, kPackageSource),
      unsupported(kUidSignal, kUidSource),
      unsupported(kCodePathSignal, kCodePathSource),
  };
#endif
}

}  // namespace rasp::android::checks
