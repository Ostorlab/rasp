/// The Android emulator checks: whether the app runs on an emulator or a virtualized device rather than real hardware.
/// They report the build properties whose value is an emulator tell, so the server can weigh them.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// A function that reads the system property `name`, returning its value or nothing when it is unset. The probe takes
/// one so a test can supply the property values without a device.
using PropertyReader = std::optional<std::string> (*)(std::string_view name);

/// Runs the emulator checks and returns what they observed.
///
/// On Android it reads the build properties through the system property store. Anywhere else the observation is
/// unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: emu.props through system_property.
[[nodiscard]] std::vector<Observation> emulator();

/// Reports the build properties whose value is an emulator tell, read through `read_property`.
///
/// An emulator or a virtualized Android image leaves its mark in the build properties: the hardware is `goldfish` or
/// `ranchu` (the Android emulator's two machines), the QEMU flags `ro.kernel.qemu` and `ro.boot.qemu` are set, and the
/// product name, model and device carry `sdk`, `emulator` or `generic`. This probe reads a fixed set of properties and
/// reports each one whose value holds such a tell, as `name=value`. A real device sets these to its own hardware and
/// product names, so none match and the probe reports nothing.
///
/// @param read_property The function that reads a property's value, the system property store on a device.
/// @return One emu.props observation read through system_property: the matching `name=value` pairs. It never has an
/// error status; a property that is unset or doesn't carry a tell is simply left out.
[[nodiscard]] Observation observe_emulator_props(PropertyReader read_property);

}  // namespace rasp::android::checks
