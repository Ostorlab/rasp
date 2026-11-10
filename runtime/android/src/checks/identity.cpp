/// The Android app-identity self-check: the package-name probe over the process's command line, the user-id probe over
/// the process's own uid, the code-path probe over the runtime's own library load path, the signer probe over the APK
/// Signing Block, and their unsupported results off Android.

#include "checks/identity.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef __ANDROID__
#include <android/api-level.h>
#include <unistd.h>

#include "apk/archive.h"
#include "apk/location.h"
#endif

#include "checks/integrity.h"
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

/// The signal of the signer probe.
constexpr std::string_view kSignerSignal = "sig.cert_sha256";
/// The source of the signer probe, the APK Signing Block of the APK the app runs from.
constexpr std::string_view kSignerSource = "apk_signing_block";

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

Observation observe_signer(const std::optional<std::vector<std::uint8_t>>& certificate) {
  if (!certificate) {
    return failed(kSignerSignal, kSignerSource);
  }
  const std::optional<std::string> digest = sha256_hex(*certificate);
  if (!digest) {
    return failed(kSignerSignal, kSignerSource);
  }
  return observed(kSignerSignal, kSignerSource, *digest);
}

std::vector<Observation> identity() {
#ifdef __ANDROID__
  const std::optional<std::string> code_path = apk::self_library_path();
  const std::optional<std::string> apk_path = apk::self_apk_path();
  const int api_level = android_get_device_api_level();
  return {
      observe_package(kCmdlinePath),
      observe_uid(static_cast<std::int64_t>(getuid())),
      observe_code_path(code_path.value_or(std::string())),
      observe_signer(apk_path && api_level > 0
                         ? apk::read_signing_certificate(*apk_path, static_cast<std::uint32_t>(api_level))
                         : std::nullopt),
  };
#else
  return {
      unsupported(kPackageSignal, kPackageSource),
      unsupported(kUidSignal, kUidSource),
      unsupported(kCodePathSignal, kCodePathSource),
      unsupported(kSignerSignal, kSignerSource),
  };
#endif
}

}  // namespace rasp::android::checks
