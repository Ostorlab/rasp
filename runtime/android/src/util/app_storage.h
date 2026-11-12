/// The app's own storage on Android: its package name, and the folder of its private storage that keeps the install id.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace rasp::android::util {

/// The package name in `cmdline`, the process's command line. Android sets the command line to the process name, whose
/// first NUL-separated field is the package, optionally followed by a private `:<name>` suffix for a process an app
/// declares with a private `android:process` (such as `com.example:remote`). Taking the part before that colon gives
/// the same package for every private process of a multi-process app. A global `android:process` name (such as
/// `com.other:remote`) has a different process name before the colon, not the package, so for those this read isn't the
/// package.
///
/// @param cmdline The process's command line.
/// @return The package name, empty when there is no name.
[[nodiscard]] std::string_view package_name(std::string_view cmdline);

/// The `no_backup` folder of the app's private storage, `/data/user/<user>/<package>/no_backup`. Android never backs it
/// up, so an id restored from a backup is never shared by two devices.
///
/// @param package The app's package name.
/// @param uid The process's uid, whose Android user is `uid / 100000`.
/// @return The folder's path.
[[nodiscard]] std::string no_backup_directory(std::string_view package, std::uint32_t uid);

/// Finds the `no_backup` folder of this app, from the process's command line and uid, and creates it when it doesn't
/// exist yet, as Android does the first time the app asks for it.
///
/// @return The folder, or nothing when the command line can't be read or the folder can't be created.
[[nodiscard]] std::optional<std::string> make_no_backup_directory();

}  // namespace rasp::android::util
