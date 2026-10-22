/// File helpers for the tests: a temporary directory that removes itself, and a function that writes a file.

#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>

namespace rasp::test_support {

/// An empty temporary directory, removed with everything in it when the object goes away.
class TemporaryDirectory {
 public:
  /// Creates the directory. Its path is empty when it couldn't be created.
  TemporaryDirectory() {
    std::error_code error;
    std::string pattern = (std::filesystem::temp_directory_path(error) / "rasp-test-XXXXXX").string();
    if (mkdtemp(pattern.data()) != nullptr) {
      path_ = pattern;
    }
  }
  /// Deleted: a copy would remove the same directory twice.
  TemporaryDirectory(const TemporaryDirectory&) = delete;
  /// Deleted: a copy would remove the same directory twice.
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
  /// Deleted: a moved-from object would still remove the directory.
  TemporaryDirectory(TemporaryDirectory&&) = delete;
  /// Deleted: a moved-from object would still remove the directory.
  TemporaryDirectory& operator=(TemporaryDirectory&&) = delete;
  /// Removes the directory and everything in it.
  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  /// The path of the directory, or empty when it couldn't be created.
  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  /// The path of the directory.
  std::string path_;
};

/// Creates a file at `path` that holds `content`, replacing any file already there.
///
/// A write that stores only part of what is left, or that a signal interrupts, is retried until the whole content is
/// written.
///
/// @param path The file to create.
/// @param content What the file holds.
/// @return `true` when the whole content was written and the file was closed.
[[nodiscard]] inline bool write_file(const std::string& path, std::string_view content) {
  const int descriptor = creat(path.c_str(), S_IRUSR | S_IWUSR);
  if (descriptor < 0) {
    return false;
  }
  bool written = true;
  while (!content.empty()) {
    const ssize_t count = write(descriptor, content.data(), content.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      written = false;
      break;
    }
    content.remove_prefix(static_cast<std::size_t>(count));
  }
  const bool closed = close(descriptor) == 0;
  return written && closed;
}

}  // namespace rasp::test_support
