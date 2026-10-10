/// Uuid, a UUID, with random_uuid, which makes a random one, and to_string, which writes its text form.

#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace rasp {

/// A UUID: 16 bytes, written as text in the usual form, such as 0f8c2e1a-7b3d-4c5e-9a1b-2c3d4e5f6a7b.
struct Uuid {
  /// The 16 bytes, in the order the text form writes them: the first byte gives the first two hex digits.
  std::array<std::uint8_t, 16> bytes{};

  /// Compares two UUIDs byte by byte.
  ///
  /// @param left The first UUID.
  /// @param right The second UUID.
  /// @return `true` when all 16 bytes of both are equal.
  [[nodiscard]] friend bool operator==(const Uuid& left, const Uuid& right) = default;
};

/// Makes a random UUID, version 4.
///
/// Its 122 random bits come from arc4random_buf, which can't fail. The other 6 bits mark the version and the variant,
/// so the text form always has the shape xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx, where y is 8, 9, a or b.
///
/// @return The new UUID.
[[nodiscard]] Uuid random_uuid();

/// Writes a UUID in its usual text form.
///
/// The text has 36 characters: the 16 bytes as 32 lowercase hex digits, two per byte, in groups of 8, 4, 4, 4 and 12,
/// separated by dashes. Any 16 bytes can be written, not only those of a version 4 UUID.
///
/// @param uuid The UUID to write.
/// @return The text form, such as 0f8c2e1a-7b3d-4c5e-9a1b-2c3d4e5f6a7b.
[[nodiscard]] std::string to_string(const Uuid& uuid);

}  // namespace rasp
