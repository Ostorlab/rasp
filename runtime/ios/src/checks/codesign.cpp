/// The iOS code-signing status check: reads the app's live `CS_*` flags through the csops system call and reports
/// them. csops and the `CS_*` flags are not in the iOS SDK, so this file makes the call by its system-call number and
/// defines the flags it reads from the kernel's `bsd/sys/codesign.h`.

#include "checks/codesign.h"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <optional>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the flags mean anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the flags mean anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The source every code-signing observation is read through.
constexpr std::string_view kSource = "csops";

/// The signal that reports whether the app's code signature is still valid.
constexpr std::string_view kValidSignal = "cs.valid";
/// The signal that reports whether a debugger is or was attached.
constexpr std::string_view kDebuggedSignal = "cs.debugged";
/// The signal that reports whether the build lets another process inspect its task.
constexpr std::string_view kGetTaskAllowSignal = "cs.get_task_allow";
/// The signal that reports whether library validation is enforced.
constexpr std::string_view kLibraryValidationSignal = "cs.library_validation";

/// The signals the check reports, in the order their observations are reported.
constexpr std::array kSignals = {kValidSignal, kDebuggedSignal, kGetTaskAllowSignal, kLibraryValidationSignal};

/// The `CS_VALID` flag: the app's code signature is still valid. From the kernel's `bsd/sys/codesign.h`, not the SDK.
constexpr std::uint32_t kCsValid = 0x00000001;
/// The `CS_GET_TASK_ALLOW` flag: the app lets another process inspect its task.
constexpr std::uint32_t kCsGetTaskAllow = 0x00000004;
/// The `CS_REQUIRE_LV` flag: the app only loads libraries signed by its own team.
constexpr std::uint32_t kCsRequireLibraryValidation = 0x00002000;
/// The `CS_DEBUGGED` flag: a debugger is or was attached to the app.
constexpr std::uint32_t kCsDebugged = 0x10000000;

/// Builds one observation per code-signing signal, each read through csops, with the status `builder` gives, for when
/// the check produces no values.
///
/// @param builder unsupported, off a physical device, or failed, when the system call fails.
/// @return One observation per signal, in order.
[[nodiscard]] std::vector<Observation> without_values(Observation (*builder)(std::string_view, std::string_view)) {
  std::vector<Observation> observations;
  observations.reserve(kSignals.size());
  for (const std::string_view signal : kSignals) {
    observations.push_back(builder(signal, kSource));
  }
  return observations;
}

#ifdef __APPLE__
/// The csops operation that returns the process's code-signing status flags.
constexpr int kCsOpsStatus = 0;

/// Reads the app's own code-signing status flags through the csops system call.
///
/// csops is not in the SDK, so the call is made by its system-call number. Reading the own process's status is always
/// allowed. There is no libc wrapper to hook: the call is the system call itself.
///
/// @return The flags, or nothing when the system call fails.
[[nodiscard]] std::optional<std::uint32_t> read_codesign_flags() {
  std::uint32_t flags = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  const long result = syscall(SYS_csops, getpid(), kCsOpsStatus, &flags, sizeof(flags));
#pragma clang diagnostic pop
  if (result != 0) {
    return std::nullopt;
  }
  return flags;
}
#endif

}  // namespace

std::vector<Observation> observe_codesign(std::uint32_t flags) {
  return {
      observed(kValidSignal, kSource, (flags & kCsValid) != 0),
      observed(kDebuggedSignal, kSource, (flags & kCsDebugged) != 0),
      observed(kGetTaskAllowSignal, kSource, (flags & kCsGetTaskAllow) != 0),
      observed(kLibraryValidationSignal, kSource, (flags & kCsRequireLibraryValidation) != 0),
  };
}

std::vector<Observation> codesign() {
  if (!kPhysicalDevice) {
    return without_values(unsupported);
  }
#ifdef __APPLE__
  const std::optional<std::uint32_t> flags = read_codesign_flags();
  return flags.has_value() ? observe_codesign(*flags) : without_values(failed);
#else
  return without_values(unsupported);
#endif
}

}  // namespace rasp::ios::checks
