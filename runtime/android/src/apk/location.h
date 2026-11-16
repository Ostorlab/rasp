/// Finding, at run time, the APK the library runs from and the directory the app's native libraries load from.

#pragma once

#include <optional>
#include <string>

namespace rasp::android::apk {

/// The raw load path of librasp.so, as the dynamic linker records it for an address inside the library.
///
/// This is the unmodified `dli_fname` from `dladdr`. An extracted library gives a plain path such as
/// `/data/app/~~.../com.example-<suffix>/lib/<abi>/librasp.so`, and a library mapped straight from the APK (when AGP
/// packages it uncompressed, with `android:extractNativeLibs="false"`, the common modern default) gives a path with the
/// `!/` separator: `.../base.apk!/lib/<abi>/librasp.so` for a single APK, or
/// `.../split_config.arm64_v8a.apk!/lib/arm64-v8a/librasp.so` for an app-bundle install. `self_apk_path`,
/// `self_library_dir` and the identity check's id.code_path all build on it, so the anchor choice, the null handling
/// and the `!/` form stay in one place.
///
/// @return The load path, or nothing when it cannot be read.
[[nodiscard]] std::optional<std::string> self_library_path();

/// The filesystem path of the APK this process runs from.
///
/// librasp.so ships inside the protected APK. When the library is mapped straight from the APK, because the app sets
/// `android:extractNativeLibs="false"`, the path is taken from the library's own load path. Otherwise it is read from
/// the process's memory map, where the APK is mapped for its resources.
///
/// @return The APK path, or nothing when it cannot be found.
[[nodiscard]] std::optional<std::string> self_apk_path();

/// The directory the app's native libraries load from, which is the directory that holds librasp.so.
///
/// It is passed to the class loader built over the decrypted dex files, so the app's own native libraries load with
/// `System.loadLibrary` the way they would in the unprotected app.
///
/// @return The native-library directory, or nothing when it cannot be found.
[[nodiscard]] std::optional<std::string> self_library_dir();

/// Whether the process's uid is the one that owns the package's data directory, as an installed app's process
/// always is. The package's name comes from the APK's install path, the way the schedule's package record reads
/// it, and `/data/user/<user>/<package>` is stat-ed, where the user is the process uid's user id. A host that
/// runs a genuine install inside another app's process carries the host's uid, which does not own the package's
/// directory, so the fact flips; a stat that fails reads as a flip, so nothing decrypts on the process's own
/// failure either.
///
/// @param apk_path The base APK's path, as the runtime resolved it.
/// @return Whether the process's uid owns the package's data directory.
[[nodiscard]] bool owns_package_data(const std::string& apk_path);

}  // namespace rasp::android::apk
