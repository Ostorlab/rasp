/// The Android app-identity self-check: whether the app still has the identity it shipped with, which a repackaged or
/// cloned build changes. It reports the running package name; the server compares it against the value the packer
/// recorded and decides.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the app-identity check and returns what it observed.
///
/// On Android it reports the running package name, read from the process's own command line. Anywhere else the
/// observation is unsupported instead, so the server still sees that the check ran.
///
/// @return One id.package observation through proc_cmdline.
[[nodiscard]] std::vector<Observation> identity();

/// Reports the running package name, read from the command line at `cmdline_path`.
///
/// Android sets a process's command line to its process name, so `/proc/self/cmdline` names the app the runtime is
/// running inside. The package is the first NUL-separated field, up to an optional `:<name>` suffix that marks a
/// process an app declares with `android:process` (such as `com.example:remote`); taking the part before the colon
/// gives the same package for every process of a multi-process app. This load-time read is the package name for the
/// main and private processes, but not for a global `android:process` name, where the process name isn't the package.
/// A clone or a repackaged app published under a different package name reports a package that doesn't match the one
/// the packer recorded.
///
/// @param cmdline_path The command line to read, `/proc/self/cmdline` on a device.
/// @return One id.package observation read through proc_cmdline: the package name. It has an error status when the file
/// can't be read or holds no name.
[[nodiscard]] Observation observe_package(std::string_view cmdline_path);

}  // namespace rasp::android::checks
