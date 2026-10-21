/// Finding, at run time, the APK the library runs from and the directory the app's native libraries load from.

#pragma once

#include <optional>
#include <string>

namespace rasp::android::apk {

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

}  // namespace rasp::android::apk
