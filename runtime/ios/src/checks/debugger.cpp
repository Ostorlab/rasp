/// The iOS debugger checks: the traced-flag, parent-process and exception-port probes, and their unsupported result off
/// a physical device.

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
#include <mach/exception_types.h>
#include <mach/kern_return.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/task.h>
#include <mach/thread_status.h>
#include <ranges>
#include <sys/proc.h>
#include <sys/syscall.h>
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
/// The source of the traced-flag probe's first read, the libc sysctl.
constexpr std::string_view kTracedSource = "sysctl";
/// The source of the traced-flag probe's second read, a direct system call a hook on the libc sysctl never runs.
constexpr std::string_view kTracedSyscallSource = "syscall";
/// The signal of the parent-process probe.
constexpr std::string_view kParentSignal = "dbg.parent";
/// The source of the parent-process probe.
constexpr std::string_view kParentSource = "getppid";
/// The signal of the exception-port probe.
constexpr std::string_view kExceptionPortsSignal = "dbg.exception_ports";
/// The source of the exception-port probe.
constexpr std::string_view kExceptionPortsSource = "task_get_exception_ports";

/// One debugger probe: the signal and source it reports, and the function that observes them.
struct Probe {
  /// The observation's signal, such as dbg.traced.
  std::string_view signal;
  /// The observation's source, such as sysctl.
  std::string_view source;
  /// Runs the probe and returns its observation.
  Observation (*observe)();
};

/// The probes the debugger checks run, in the order their observations are reported. The traced signal that one
/// libc function can hide is read through a second, independent source, so a hook on one source leaves the two
/// disagreeing.
constexpr std::array kProbes = {
    Probe{.signal = kTracedSignal, .source = kTracedSource, .observe = observe_traced},
    Probe{.signal = kTracedSignal, .source = kTracedSyscallSource, .observe = observe_traced_syscall},
    Probe{.signal = kParentSignal, .source = kParentSource, .observe = observe_parent},
    Probe{.signal = kExceptionPortsSignal, .source = kExceptionPortsSource, .observe = observe_exception_ports},
};

#ifdef __APPLE__
/// Whether `info` has the kernel's traced flag set, which means a debugger is attached to the process.
///
/// @param info The process's `kinfo_proc` entry.
/// @return Whether its `p_flag` has `P_TRACED`.
[[nodiscard]] bool is_traced(const kinfo_proc& info) {
  const auto flags = static_cast<std::uint32_t>(info.kp_proc.p_flag);
  return (flags & static_cast<std::uint32_t>(P_TRACED)) != 0;
}

/// Reads the app's own `kinfo_proc` entry into `info`.
///
/// With `direct` false it makes the request through the libc sysctl; with `direct` true it makes the same request as
/// a direct system call, which a hook on the libc sysctl never runs. A hook that lies to one path and not the other
/// makes two reads of the same fact disagree.
///
/// @param info Set to the process's `kinfo_proc` entry when the read returns a whole one.
/// @param direct Whether to make the request as a direct system call rather than through the libc sysctl.
/// @return Whether the read returned a whole `kinfo_proc` entry.
[[nodiscard]] bool read_process_info(kinfo_proc& info, bool direct) {
  std::array<int, 4> name = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
  std::size_t size = sizeof(info);
  const auto length = static_cast<unsigned int>(name.size());
  int result = 0;
  if (direct) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    result = static_cast<int>(syscall(SYS_sysctl, name.data(), length, &info, &size, nullptr, 0));
#pragma clang diagnostic pop
  } else {
    result = sysctl(name.data(), length, &info, &size, nullptr, 0);
  }
  return result == 0 && size == sizeof(info);
}
#endif

}  // namespace

Observation observe_traced() {
#ifdef __APPLE__
  kinfo_proc info{};
  if (!read_process_info(info, false)) {
    return failed(kTracedSignal, kTracedSource);
  }
  return observed(kTracedSignal, kTracedSource, is_traced(info));
#else
  return unsupported(kTracedSignal, kTracedSource);
#endif
}

Observation observe_traced_syscall() {
#ifdef __APPLE__
  kinfo_proc info{};
  if (!read_process_info(info, true)) {
    return failed(kTracedSignal, kTracedSyscallSource);
  }
  return observed(kTracedSignal, kTracedSyscallSource, is_traced(info));
#else
  return unsupported(kTracedSignal, kTracedSyscallSource);
#endif
}

Observation observe_parent() { return observed(kParentSignal, kParentSource, static_cast<std::int64_t>(getppid())); }

Observation observe_exception_ports() {
#ifdef __APPLE__
  std::array<exception_mask_t, EXC_TYPES_COUNT> masks{};
  std::array<mach_port_t, EXC_TYPES_COUNT> ports{};
  std::array<exception_behavior_t, EXC_TYPES_COUNT> behaviors{};
  std::array<thread_state_flavor_t, EXC_TYPES_COUNT> flavors{};
  auto count = static_cast<mach_msg_type_number_t>(masks.size());
  if (task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks.data(), &count, ports.data(), behaviors.data(),
                               flavors.data()) != KERN_SUCCESS ||
      count > masks.size()) {
    return failed(kExceptionPortsSignal, kExceptionPortsSource);
  }
  exception_mask_t masks_with_port = 0;
  bool released = true;
  for (const auto [mask, port] : std::views::zip(masks, ports) | std::views::take(count)) {
    if (MACH_PORT_VALID(port)) {
      masks_with_port |= mask;
      if (mach_port_deallocate(mach_task_self(), port) != KERN_SUCCESS) {
        released = false;
      }
    }
  }
  if (!released) {
    return failed(kExceptionPortsSignal, kExceptionPortsSource);
  }
  return observed(kExceptionPortsSignal, kExceptionPortsSource, static_cast<std::int64_t>(masks_with_port));
#else
  return unsupported(kExceptionPortsSignal, kExceptionPortsSource);
#endif
}

std::vector<Observation> debugger() {
  std::vector<Observation> observations;
  observations.reserve(kProbes.size());
  for (const Probe& probe : kProbes) {
    observations.push_back(kPhysicalDevice ? probe.observe() : unsupported(probe.signal, probe.source));
  }
  return observations;
}

}  // namespace rasp::ios::checks
