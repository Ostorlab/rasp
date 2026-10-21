/// Dex, one dex file of the protected app, and unpack, which recovers the app's dex files from the packer's payload.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rasp::android::payload {

/// One dex file of the protected app.
struct Dex {
  /// The file's name in the original app, such as classes.dex.
  std::string name;
  /// The file's bytes.
  std::vector<std::uint8_t> data;

  /// Compares two dex files field by field.
  ///
  /// @param left The first dex file.
  /// @param right The second dex file.
  /// @return `true` when both have the same name and the same bytes.
  [[nodiscard]] friend bool operator==(const Dex& left, const Dex& right) = default;
};

/// The most dex files a payload may hold. An app has a few dozen at most; the limit bounds what unpack allocates for a
/// forged payload.
inline constexpr std::uint32_t kMaxDexFiles = 1024;

/// Decrypts the packer's payload and reads the app's dex files from it.
///
/// The payload is one frame of the packer's cipher (see decrypt). Its decrypted bytes start with the number of dex
/// files. Then each dex file follows, in load order: the length of its name, its name, the length of its bytes, and
/// its bytes. The number and the lengths are big-endian 32-bit numbers. Bytes after the last dex file are ignored.
///
/// @param key The payload key, kKeySize bytes long.
/// @param frame The payload, as the packer wrote it.
/// @return The dex files, in load order. Nothing when the frame can't be decrypted, when it holds more than
/// kMaxDexFiles dex files, or when a number or a length goes past the end of the decrypted bytes.
[[nodiscard]] std::optional<std::vector<Dex>> unpack(std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> frame);

}  // namespace rasp::android::payload
