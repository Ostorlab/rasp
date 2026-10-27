/// The iOS emulator check: the compile-time and the sysctl Simulator tells, and their unsupported results off an Apple
/// host.

#include "checks/emulator.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <sys/sysctl.h>
#endif

namespace rasp::ios::checks {

namespace {

/// The signal both tells report.
constexpr std::string_view kSimulatorSignal = "emu.simulator";
/// The source of the compile-time tell.
constexpr std::string_view kTargetConditionalsSource = "target_conditionals";
/// The source of the sysctl tell.
constexpr std::string_view kSysctlSource = "sysctl";

#ifdef __APPLE__
/// The `hw.machine` name the sysctl tell reads.
constexpr std::string_view kMachineName = "hw.machine";
/// The most bytes of `hw.machine` the probe accepts. A real model identifier is far shorter.
constexpr std::size_t kMaxMachineSize = 64;
#endif

/// The machine identifiers the Simulator reports through `hw.machine`: the host Mac's architecture, which no physical
/// iOS device reports.
constexpr auto kSimulatorMachines = std::to_array<std::string_view>({
    "x86_64",
    "arm64",
    "i386",
});

}  // namespace

Observation observe_target_conditionals() {
#ifdef __APPLE__
  return observed(kSimulatorSignal, kTargetConditionalsSource, static_cast<bool>(TARGET_OS_SIMULATOR));
#else
  return unsupported(kSimulatorSignal, kTargetConditionalsSource);
#endif
}

Observation observe_machine_tell(std::string_view machine) {
  const bool is_simulator =
      std::ranges::any_of(kSimulatorMachines, [machine](std::string_view name) { return name == machine; });
  return observed(kSimulatorSignal, kSysctlSource, is_simulator);
}

Observation observe_machine() {
#ifdef __APPLE__
  std::array<char, kMaxMachineSize> buffer{};
  std::size_t size = buffer.size();
  if (sysctlbyname(kMachineName.data(), buffer.data(), &size, nullptr, 0) != 0 || size == 0 ||
      size > buffer.size() || buffer[size - 1] != '\0') {
    return failed(kSimulatorSignal, kSysctlSource);
  }
  return observe_machine_tell(std::string_view(buffer.data(), size - 1));
#else
  return unsupported(kSimulatorSignal, kSysctlSource);
#endif
}

std::vector<Observation> emulator() { return {observe_target_conditionals(), observe_machine()}; }

}  // namespace rasp::ios::checks
