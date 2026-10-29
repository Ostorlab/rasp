/// The app's internal data directory on Android, derived from /proc/self/cmdline.

#pragma once

#include <optional>
#include <string>

namespace rasp::android {

/// The app's internal data directory, such as `/data/data/com.example.app/files`.
///
/// Android gives each app a private directory under `/data/data/<package>/files` (or `/data/user/0/<package>/files` on
/// some devices). The package name is read from `/proc/self/cmdline`, which Android sets to the process name.
///
/// @return The directory path, or nothing when the package name cannot be read.
[[nodiscard]] std::optional<std::string> data_dir();

}  // namespace rasp::android
