/// The installation id: a random UUID generated on first launch and persisted for the life of the install.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace rasp {

/// The number of bytes in an installation id.
inline constexpr std::size_t kInstallIdBytes = 16;

/// A 16-byte installation id.
using InstallId = std::array<std::uint8_t, kInstallIdBytes>;

/// Loads the installation id from the file at `path`, or generates a new one, writes it to `path` and returns it.
///
/// The id is a 16-byte UUID v4 read from the platform's random source. It is written as 16 raw bytes, and a file that
/// exists but does not hold exactly 16 bytes is replaced with a fresh id.
///
/// @param dir The directory to store the id in, such as the app's internal files directory. It must exist.
/// @return The id, or nothing when the random source, the directory or the file cannot be read or written.
[[nodiscard]] std::optional<InstallId> get_or_create_install_id(std::string_view dir);

}  // namespace rasp
