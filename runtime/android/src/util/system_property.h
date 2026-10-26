/// Reading Android system properties, shared by the checks that look for tells in them.

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace rasp::android::util {

/// A function that reads the system property `name`, returning its value or nothing when it is unset. A check takes one
/// so a test can supply the property values without a device.
using PropertyReader = std::optional<std::string> (*)(std::string_view name);

/// Reads the system property `name` through the property store, or nothing when it is unset.
///
/// A property that is set but empty returns the empty string, not nothing, so a bare flag property (such as a QEMU
/// flag) is still reported. Off Android there is no property store, so it always returns nothing.
///
/// @param name The property to read, such as `ro.hardware`.
/// @return The property's value, the empty string when it is set but empty, or nothing when it is unset.
[[nodiscard]] std::optional<std::string> read_system_property(std::string_view name);

}  // namespace rasp::android::util
