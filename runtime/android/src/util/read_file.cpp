/// read_file, which reads a whole file up to a size limit.

#include "util/read_file.h"

#include <array>
#include <cstddef>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

namespace gsl {

/// Marks a raw pointer that owns what it points to, as the Guidelines Support Library does, so clang-tidy checks it.
template <typename T>
// NOLINTNEXTLINE(readability-identifier-naming): gsl::owner keeps the GSL's exact lowercase name so cppcoreguidelines-owning-memory recognizes it.
using owner = T;

}  // namespace gsl

namespace rasp::android::util {

namespace {

/// Reads `file` to its end, or gives nothing when a read fails or the content is longer than `limit` bytes.
[[nodiscard]] std::optional<std::string> read_all(std::FILE* file, std::size_t limit) {
  std::string content;
  std::array<char, 1024> chunk{};
  while (true) {
    const std::size_t count = std::fread(chunk.data(), 1, chunk.size(), file);
    if (count > limit - content.size()) {
      return std::nullopt;
    }
    content.append(chunk.data(), count);
    if (std::ferror(file) != 0) {
      return std::nullopt;
    }
    if (std::feof(file) != 0) {
      return content;
    }
  }
}

}  // namespace

std::optional<std::string> read_file(std::string_view path, std::size_t limit) {
  const std::string name(path);
  const gsl::owner<std::FILE*> file = std::fopen(name.c_str(), "re");
  if (file == nullptr) {
    return std::nullopt;
  }
  std::optional<std::string> content = read_all(file, limit);
  if (std::fclose(file) != 0) {
    return std::nullopt;
  }
  return content;
}

}  // namespace rasp::android::util
