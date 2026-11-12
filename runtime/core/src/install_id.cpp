/// load_or_create_install_id, which reads the install id kept in the app's own storage, or creates and keeps one.

#include "rasp/install_id.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <unistd.h>
#include <utility>

#include "rasp/util/read_file.h"
#include "rasp/util/uuid.h"

namespace gsl {

/// Marks a raw pointer that owns what it points to, as the Guidelines Support Library does, so clang-tidy checks it.
template <typename T>
// NOLINTNEXTLINE(readability-identifier-naming): gsl::owner keeps the GSL's exact lowercase name so cppcoreguidelines-owning-memory recognizes it.
using owner = T;

}  // namespace gsl

namespace rasp {

namespace {

/// The length of a UUID's text: 32 hex digits and 4 hyphens.
constexpr std::size_t kUuidLength = 36;

/// The suffix of the lock file next to the id's file, which the processes of the app lock while one of them creates the
/// id.
constexpr std::string_view kLockSuffix = ".lock";

/// The suffix of the temporary file next to the id's file, which a new id is written to before it is renamed over it.
constexpr std::string_view kTemporarySuffix = ".tmp";

/// The permissions of the lock file: only the app can read and write it.
constexpr int kLockFileMode = 0600;

/// How many times taking the lock is tried when a signal interrupts it.
constexpr int kLockAttempts = 3;

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

/// Writes `content` to a new file at `path`.
///
/// @param path The file.
/// @param content What it must hold.
/// @return `true` when the file holds `content`.
[[nodiscard]] bool write_file(const std::string& path, std::string_view content) {
  const gsl::owner<std::FILE*> file = std::fopen(path.c_str(), "we");
  if (file == nullptr) {
    return false;
  }
  const bool written = std::fwrite(content.data(), 1, content.size(), file) == content.size();
  return std::fclose(file) == 0 && written;
}

/// The id kept in the file at `path`.
///
/// @param path The file that keeps the id.
/// @return The id, or nothing when the file can't be read or doesn't hold a UUID as load_or_create_install_id writes
/// it.
[[nodiscard]] std::optional<std::string> read_id(const std::string& path) {
  std::optional<std::string> kept = util::read_file(path, kUuidLength);
  if (!kept.has_value() || !is_uuid(*kept)) {
    return std::nullopt;
  }
  return kept;
}

/// Keeps `id` in the file at `path`, replacing it: the id is written whole to the temporary file next to it, which is
/// then renamed, so a process never reads half an id. Only the process that holds the lock calls it, so the temporary
/// file has one name, and one a crash left before its rename is overwritten by the next one.
///
/// @param path The file that keeps the id.
/// @param id The new id.
/// @return `true` when the file holds `id`.
[[nodiscard]] bool keep(const std::string& path, const std::string& id) {
  const std::string temporary = path + std::string(kTemporarySuffix);
  if (!write_file(temporary, id) || std::rename(temporary.c_str(), path.c_str()) != 0) {
    static_cast<void>(std::remove(temporary.c_str()));
    return false;
  }
  return true;
}

/// Opens the lock file at `path`, creating it when it doesn't exist, and takes its exclusive lock. It waits while
/// another process of the app holds the lock. The lock is released when the descriptor is closed, or when the process
/// that holds it ends.
///
/// @param path The lock file.
/// @return The lock file's descriptor, which holds the lock, or nothing when the file can't be opened or locked.
[[nodiscard]] std::optional<int> lock(const std::string& path) {
  // open is a libc variadic function, and its flags come from the included <fcntl.h>.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner)
  const int descriptor = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, kLockFileMode);
  if (descriptor < 0) {
    return std::nullopt;
  }
  for (int attempt = 0; attempt < kLockAttempts; ++attempt) {
    // LOCK_EX comes from the included <sys/file.h>, which takes it from the system's own headers on Android.
    // NOLINTNEXTLINE(misc-include-cleaner)
    if (flock(descriptor, LOCK_EX) == 0) {
      return descriptor;
    }
    if (errno != EINTR) {
      break;
    }
  }
  static_cast<void>(close(descriptor));
  return std::nullopt;
}

}  // namespace

std::optional<std::string> load_or_create_install_id(std::string_view directory) {
  std::string path(directory);
  path.push_back('/');
  path.append(kInstallIdFileName);
  std::optional<std::string> kept = read_id(path);
  if (kept.has_value()) {
    return kept;
  }
  const std::optional<int> locked = lock(path + std::string(kLockSuffix));
  if (!locked.has_value()) {
    return std::nullopt;
  }
  kept = read_id(path);
  if (!kept.has_value()) {
    std::string created = util::new_uuid();
    if (keep(path, created)) {
      kept = std::move(created);
    }
  }
  static_cast<void>(close(*locked));
  return kept;
}

}  // namespace rasp
