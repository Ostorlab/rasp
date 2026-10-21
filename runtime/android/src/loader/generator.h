/// The native dex generator: produces the decrypted dex that defines a requested class, for the Java loader.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::android::loader {

/// One decrypted dex and the binary names of the classes it defines.
struct GeneratedDex {
  /// The decrypted dex bytes.
  std::vector<std::uint8_t> bytes;
  /// The binary names of every class the dex defines.
  std::vector<std::string> class_names;
};

/// Produces the decrypted dex that defines `class_name`.
///
/// It reads the packer's class-to-dex map and the encrypted dex from the app's own APK and decrypts the dex with the
/// key from the APK. The map and key are read once, on the first call, and kept for the life of the process.
///
/// @param class_name The binary name of the class to produce, such as `com.example.Main`.
/// @return The decrypted dex and the classes it defines. Nothing when `class_name` is not a class the packer split out,
/// or when the dex can't be read or decrypted.
[[nodiscard]] std::optional<GeneratedDex> generate(std::string_view class_name);

}  // namespace rasp::android::loader
