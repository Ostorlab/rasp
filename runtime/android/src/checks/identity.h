/// The Android app-identity self-check: whether the app still has the identity it shipped with, which a repackaged or
/// cloned build changes. It reports the running package name and the process's own user id; the server compares them
/// against the values the packer recorded and decides.

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the app-identity check and returns what it observed.
///
/// On Android it reports the running package name, read from the process's own command line, and the process's own user
/// id, read from getuid. Anywhere else both observations are unsupported instead, so the server still sees that the
/// check ran.
///
/// @return Two observations: id.package through proc_cmdline, then id.uid through getuid.
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

/// Reports the process's own user id `uid`.
///
/// Android gives every app a uid of `user_id * 100000 + app_id`, where app_id is 10000-19999 for a normal app, so the
/// uid of the main user's apps is 10000-99999 and a secondary user's apps (a work profile, an OEM "Dual Apps" clone, or
/// an added user) start at 100000. The uid alone therefore tells which user the app runs under: `uid / 100000` is 0 for
/// the main install and 1 or more for a copy running in a separate user. This probe reports the raw uid as a fact; the
/// server does the arithmetic and decides, since a work profile is legitimate while a cloned banking app may not be. It
/// doesn't catch a third-party cloner (such as Parallel Space) that runs under the host's own uid; that needs the data
/// path, left to a later probe.
///
/// @param uid The process's own user id, from getuid on a device.
/// @return One id.uid observation through getuid: the uid as an integer.
[[nodiscard]] Observation observe_uid(std::int64_t uid);

}  // namespace rasp::android::checks
