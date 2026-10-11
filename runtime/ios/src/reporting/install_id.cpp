/// load_install_id: keeps the install id in a 16-byte file, written through a temporary file.

#include "reporting/install_id.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <sys/stat.h>

#include "rasp/util/uuid.h"

namespace gsl {

/// Marks a raw pointer that owns what it points to, as the Guidelines Support Library does, so clang-tidy checks it.
template <typename T>
using owner = T;

}  // namespace gsl

namespace rasp::ios {

namespace {

/// The size of a stored install id, in bytes.
constexpr std::size_t kIdSize = Uuid{}.bytes.size();

/// What a temporary file's name adds to the real file's name while the id is being written.
constexpr std::string_view kTemporarySuffix = ".tmp";

/// What reading the stored id found.
enum class Found : std::uint8_t {
  /// The file holds an id.
  kId,
  /// There's no usable id: the file is missing, or isn't exactly 16 bytes long.
  kNothing,
  /// The file exists but couldn't be read.
  kUnreadable,
};

/// What reading the stored id found, and the id when there is one.
struct Stored {
  /// What reading found.
  Found found = Found::kNothing;
  /// The stored id, when `found` is kId.
  Uuid id;
};

/// Reads the id stored in the file at `path`.
[[nodiscard]] Stored read_stored(const std::string& path) {
  gsl::owner<std::FILE*> file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return {.found = errno == ENOENT ? Found::kNothing : Found::kUnreadable, .id = {}};
  }
  std::array<std::uint8_t, kIdSize + 1> buffer{};
  const std::size_t size = std::fread(buffer.data(), 1, buffer.size(), file);
  const bool failed = std::ferror(file) != 0;
  const bool closed = std::fclose(file) == 0;
  if (failed || !closed) {
    return {.found = Found::kUnreadable, .id = {}};
  }
  if (size != kIdSize) {
    return {.found = Found::kNothing, .id = {}};
  }
  Stored stored{.found = Found::kId, .id = {}};
  std::copy_n(buffer.begin(), kIdSize, stored.id.bytes.begin());
  return stored;
}

/// Creates `directory` when it doesn't exist yet, and says whether it exists now.
[[nodiscard]] bool ensure_directory(const std::string& directory) {
  return mkdir(directory.c_str(), S_IRWXU) == 0 || errno == EEXIST;
}

/// Writes `id` to the file at `path` through a temporary file renamed over it, and says whether it worked.
[[nodiscard]] bool store(const std::string& path, const Uuid& id) {
  const std::string temporary = path + std::string(kTemporarySuffix);
  gsl::owner<std::FILE*> file = std::fopen(temporary.c_str(), "wb");
  if (file == nullptr) {
    return false;
  }
  bool written = std::fwrite(id.bytes.data(), 1, id.bytes.size(), file) == id.bytes.size();
  written = std::fflush(file) == 0 && written;
  written = std::fclose(file) == 0 && written;
  if (written && std::rename(temporary.c_str(), path.c_str()) == 0) {
    return true;
  }
  static_cast<void>(std::remove(temporary.c_str()));
  return false;
}

}  // namespace

Uuid load_install_id(const std::string& directory) noexcept {
  const std::string path = directory + "/" + std::string(kInstallIdFileName);
  const Stored stored = read_stored(path);
  if (stored.found == Found::kId) {
    return stored.id;
  }
  const Uuid id = random_uuid();
  if (stored.found == Found::kNothing && ensure_directory(directory)) {
    static_cast<void>(store(path, id));
  }
  return id;
}

}  // namespace rasp::ios
