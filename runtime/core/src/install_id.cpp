/// load_or_create_install_id, which reads the install id kept in the app's own storage, or creates and keeps one.

#include "rasp/install_id.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>

#include "rasp/util/read_file.h"

namespace gsl {

/// Marks a raw pointer that owns what it points to, as the Guidelines Support Library does, so clang-tidy checks it.
template <typename T>
// NOLINTNEXTLINE(readability-identifier-naming): gsl::owner keeps the GSL's exact lowercase name so cppcoreguidelines-owning-memory recognizes it.
using owner = T;

}  // namespace gsl

namespace rasp {

namespace {

/// The number of random bytes of a UUID.
constexpr std::size_t kUuidBytes = 16;

/// The length of a UUID's text: 32 hex digits and 4 hyphens.
constexpr std::size_t kUuidLength = 36;

/// Where a UUID's text has its hyphens.
constexpr std::array<std::size_t, 4> kHyphens{8, 13, 18, 23};

/// The hex digits, lowercase.
constexpr std::string_view kHexDigits = "0123456789abcdef";

/// Whether `text` is a UUID as load_or_create_install_id writes it: 36 characters, lowercase hex digits with hyphens
/// at kHyphens.
///
/// @param text The text to check.
/// @return `true` when it is.
[[nodiscard]] bool is_uuid(std::string_view text) {
  if (text.size() != kUuidLength) {
    return false;
  }
  for (std::size_t index = 0; index < text.size(); ++index) {
    const bool hyphen = std::ranges::find(kHyphens, index) != kHyphens.end();
    if (hyphen ? text[index] != '-' : !kHexDigits.contains(text[index])) {
      return false;
    }
  }
  return true;
}

/// Makes a new random UUID, version 4, from `arc4random_buf`, which can't fail.
///
/// @return Its text, 36 lowercase characters.
[[nodiscard]] std::string new_uuid() {
  constexpr unsigned kVersionMask = 0x0FU;
  constexpr unsigned kVersion4 = 0x40U;
  constexpr unsigned kVariantMask = 0x3FU;
  constexpr unsigned kVariantRfc = 0x80U;
  std::array<std::uint8_t, kUuidBytes> bytes{};
  arc4random_buf(bytes.data(), bytes.size());
  bytes[6] = static_cast<std::uint8_t>((unsigned{bytes[6]} & kVersionMask) | kVersion4);
  bytes[8] = static_cast<std::uint8_t>((unsigned{bytes[8]} & kVariantMask) | kVariantRfc);
  std::string text;
  text.reserve(kUuidLength);
  for (const std::uint8_t byte : bytes) {
    if (std::ranges::find(kHyphens, text.size()) != kHyphens.end()) {
      text.push_back('-');
    }
    text.push_back(kHexDigits[byte >> 4U]);
    text.push_back(kHexDigits[byte & 0x0FU]);
  }
  return text;
}

/// Writes `content` to the file at `path`, replacing it: to a temporary file next to it, which is then renamed.
///
/// @param path The file.
/// @param content What it must hold.
/// @return `true` when the file holds `content`.
[[nodiscard]] bool replace_file(const std::string& path, std::string_view content) {
  const std::string temporary = path + ".tmp." + std::to_string(getpid());
  const gsl::owner<std::FILE*> file = std::fopen(temporary.c_str(), "we");
  if (file == nullptr) {
    return false;
  }
  const bool written = std::fwrite(content.data(), 1, content.size(), file) == content.size();
  if (std::fclose(file) != 0 || !written || std::rename(temporary.c_str(), path.c_str()) != 0) {
    static_cast<void>(std::remove(temporary.c_str()));
    return false;
  }
  return true;
}

}  // namespace

std::optional<std::string> load_or_create_install_id(std::string_view directory) {
  std::string path(directory);
  path.push_back('/');
  path.append(kInstallIdFileName);
  std::optional<std::string> kept = util::read_file(path, kUuidLength);
  if (kept.has_value() && is_uuid(*kept)) {
    return kept;
  }
  std::string created = new_uuid();
  if (!replace_file(path, created)) {
    return std::nullopt;
  }
  return created;
}

}  // namespace rasp
