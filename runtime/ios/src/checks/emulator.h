/// The iOS emulator check: whether the app runs on the iOS Simulator rather than a physical device. It reports the two
/// tells it can read, so the server can weigh them.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the emulator check and returns what it observed.
///
/// Unlike the other iOS checks, this one means something off a physical device: the Simulator is exactly what it looks
/// for. It reads two tells, through two sources, and reports each as a boolean. Only on a non-Apple host, where neither
/// tell exists, is the observation unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per source, in this order: emu.simulator read through target_conditionals, then through
/// sysctl.
[[nodiscard]] std::vector<Observation> emulator();

/// Reports whether this build was compiled for the iOS Simulator, as `TARGET_OS_SIMULATOR` records at compile time.
///
/// The framework is built as a separate slice for the device and for the Simulator, so `TARGET_OS_SIMULATOR` is fixed
/// when the slice is compiled. A correctly built device binary cannot carry a `true` here, which makes this the honest
/// answer; the sysctl probe confirms it at runtime so a repacked binary cannot simply report `false`.
///
/// @return One emu.simulator observation read through target_conditionals: true on a Simulator build, false on a device
/// build, and the unsupported status on a non-Apple host where the macro doesn't exist.
[[nodiscard]] Observation observe_target_conditionals();

/// Reports whether the machine identifier `machine` is the Simulator's rather than a physical device's.
///
/// On a physical device `hw.machine` is the model identifier, such as `iPhone15,2` or `iPad13,1`. On the Simulator it
/// is the host Mac's architecture instead, `x86_64` or `arm64`, which no physical iOS device reports. This decides from
/// the string alone, so the real sysctl read can be tested through it.
///
/// @param machine The value of `hw.machine`, as sysctl returns it.
/// @return One emu.simulator observation read through sysctl: true when `machine` is a Simulator architecture, false
/// otherwise.
[[nodiscard]] Observation observe_machine_tell(std::string_view machine);

/// Reads `hw.machine` through sysctl and reports whether it is the Simulator's, as observe_machine_tell decides.
///
/// @return One emu.simulator observation read through sysctl: true or false as observe_machine_tell decides, the error
/// status when sysctl fails or returns an unterminated or over-long value, and the unsupported status on a non-Apple
/// host.
[[nodiscard]] Observation observe_machine();

}  // namespace rasp::ios::checks
