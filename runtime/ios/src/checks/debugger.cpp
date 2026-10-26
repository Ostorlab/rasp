/// The iOS debugger checks: the traced-flag and parent-process probes, and their unsupported result off a physical
/// device.

#include "checks/debugger.h"

#include <array>
#include <cstdint>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <cstddef>
#include <sys/proc.h>
#include <sys/sysctl.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the traced-flag probe.
constexpr std::string_view kTracedSignal = "dbg.traced";
/// The source of the traced-flag probe.
constexpr std::string_view kTracedSource = "sysctl";
/// The signal of the parent-process probe.
constexpr std::string_view kParentSignal = "dbg.parent";
/// The source of the parent-process probe.
constexpr std::string_view kParentSource = "getppid";

/// One debugger probe: the signal and source it reports, and the function that observes them.
struct Probe {
  /// The observation's signal, such as dbg.traced.
  std::string_view signal;
  /// The observation's source, such as sysctl.
  std::string_view source;
  /// Runs the probe and returns its observation.
  Observation (*observe)();
};

/// The probes the debugger checks run, in the order their observations are reported.
constexpr std::array kProbes = {
    Probe{.signal = kTracedSignal, .source = kTracedSource, .observe = observe_traced},
    Probe{.signal = kParentSignal, .source = kParentSource, .observe = observe_parent},
};

}  // namespace

Observation observe_traced() {
#ifdef __APPLE__
  std::array<int, 4> name = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
  kinfo_proc info{};
  std::size_t size = sizeof(info);
  if (sysctl(name.data(), static_cast<unsigned int>(name.size()), &info, &size, nullptr, 0) != 0 ||
      size != sizeof(info)) {
    return failed(kTracedSignal, kTracedSource);
  }
  const auto flags = static_cast<std::uint32_t>(info.kp_proc.p_flag);
  return observed(kTracedSignal, kTracedSource, (flags & static_cast<std::uint32_t>(P_TRACED)) != 0);
#else
  return unsupported(kTracedSignal, kTracedSource);
#endif
}

Observation observe_parent() { return observed(kParentSignal, kParentSource, static_cast<std::int64_t>(getppid())); }

std::vector<Observation> debugger() {
  std::vector<Observation> observations;
  observations.reserve(kProbes.size());
  for (const Probe& probe : kProbes) {
    observations.push_back(kPhysicalDevice ? probe.observe() : unsupported(probe.signal, probe.source));
  }
  return observations;
}

}  // namespace rasp::ios::checks
