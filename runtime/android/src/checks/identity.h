/// The Android app-identity self-check: whether the app still has the identity it shipped with, which a repackaged or
/// cloned build changes. It reports the running package name, the process's own user id, and the path the runtime's
/// code loads from; the server compares them against the values the packer recorded and decides.

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the app-identity check and returns what it observed.
///
/// On Android it reports the running package name, read from the process's own command line; the process's own user id,
/// read from getuid; and the path the runtime's library loads from, read from the dynamic loader. Anywhere else every
/// observation is unsupported instead, so the server still sees that the check ran.
///
/// @return Three observations: id.package through proc_cmdline, id.uid through getuid, then id.code_path through
/// dladdr.
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
/// Android gives every app a uid of `user_id * 100000 + app_id`, where app_id is 10000-19999 (with 99000-99999 reserved
/// for isolated processes), so the uid of the main user's apps is 10000-19999 and a secondary user's apps (a work
/// profile, an OEM "Dual Apps" clone, or an added user) land in that user's 100000-wide block (110000-119999 for user
/// 1, and so on). The uid alone therefore tells which user the app runs under: `uid / 100000` is 0 for the main install
/// and 1 or more for a copy running in a separate user. This probe reports the raw uid as a fact; the server does the
/// arithmetic and decides, since a work profile is legitimate while a cloned banking app may not be. It doesn't catch a
/// third-party virtualizer (such as Parallel Space) that runs under the host's own uid; id.code_path does.
///
/// @param uid The process's own user id, from getuid on a device.
/// @return One id.uid observation through getuid: the uid as an integer.
[[nodiscard]] Observation observe_uid(std::int64_t uid);

/// Reports the path the runtime's own library loads from, `code_path`.
///
/// A genuine install loads librasp.so from the app's own install directory under `/data/app`, whose path carries the
/// app's package: `/data/app/~~.../com.example-<suffix>/lib/<abi>/librasp.so` when the library is extracted, or, when
/// AGP packages it uncompressed (the common modern default), `/data/app/~~.../com.example-<suffix>/base.apk!/lib/<abi>
/// /librasp.so` for a single APK or `/data/app/~~.../com.example-<suffix>/split_config.arm64_v8a.apk!/lib/arm64-v8a
/// /librasp.so` for an app-bundle install. A third-party virtualizer (such as Parallel Space or VirtualApp) runs the
/// guest app inside its own process and redirects its files, so the library loads from the host app's data directory
/// instead, such as `/data/data/com.parallel.intl/.../com.example/lib/<abi>/librasp.so`. That path still contains the
/// guest package as a subdirectory, so the tell is the owning directory, not a substring: a genuine install owns
/// `/data/app/.../<guest-package>-<suffix>`, a virtualized one owns the host's `/data/data` directory. The uid is the
/// host's normal uid, so id.uid can't see this; the load path can. The probe reports the raw loader path as a fact and
/// the server compares the owning directory against the package the packer recorded. A sophisticated virtualizer can
/// fake the path, so this is a signal, not proof.
///
/// @param code_path The load path of the runtime's library, from the dynamic loader on a device.
/// @return One id.code_path observation through dladdr: the path. It has an error status when the path can't be read.
[[nodiscard]] Observation observe_code_path(std::string_view code_path);

}  // namespace rasp::android::checks
