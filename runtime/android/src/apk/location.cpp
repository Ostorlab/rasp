/// Finding the APK and the native-library directory of this process, from the library's load path and /proc/self/maps.

#include "apk/location.h"

#include <cstddef>
#include <dlfcn.h>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace rasp::android::apk {

namespace {

/// The load path of librasp.so, as the dynamic linker records it for an address inside the library.
[[nodiscard]] std::optional<std::string> library_path() {
  Dl_info info = {};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (dladdr(reinterpret_cast<const void*>(&library_path), &info) == 0 || info.dli_fname == nullptr) {
    return std::nullopt;
  }
  return std::string(info.dli_fname);
}

/// The path with its last component removed, or nothing when it has no directory part.
[[nodiscard]] std::optional<std::string> parent_dir(std::string_view path) {
  const std::size_t slash = path.find_last_of('/');
  if (slash == std::string_view::npos || slash == 0) {
    return std::nullopt;
  }
  return std::string(path.substr(0, slash));
}

/// The app's base APK, derived from an extracted library path `<app>/lib/<abi>/librasp.so`, when it is readable.
///
/// An extracted native library sits two directories below the app's install directory, next to the APK. The APK is
/// found this way even before it is mapped for the app's resources, which a load-time constructor runs ahead of.
[[nodiscard]] std::optional<std::string> apk_beside_library(std::string_view library) {
  const std::optional<std::string> abi = parent_dir(library);
  if (!abi.has_value()) {
    return std::nullopt;
  }
  const std::optional<std::string> lib = parent_dir(*abi);
  if (!lib.has_value()) {
    return std::nullopt;
  }
  const std::optional<std::string> app = parent_dir(*lib);
  if (!app.has_value()) {
    return std::nullopt;
  }
  std::string candidate = *app + "/base.apk";
  if (access(candidate.c_str(), R_OK) != 0) {
    return std::nullopt;
  }
  return candidate;
}

/// The APK path in a /proc/self/maps dump: the file-backed mapping under /data/app whose path ends in .apk.
[[nodiscard]] std::optional<std::string> apk_in_maps(std::string_view maps) {
  std::optional<std::string> fallback;
  std::size_t start = 0;
  while (start < maps.size()) {
    std::size_t end = maps.find('\n', start);
    if (end == std::string_view::npos) {
      end = maps.size();
    }
    const std::string_view line = maps.substr(start, end - start);
    start = end + 1;
    const std::size_t slash = line.find('/');
    if (slash == std::string_view::npos) {
      continue;
    }
    const std::string_view path = line.substr(slash);
    if (!path.ends_with(".apk") || !path.contains("/data/app/")) {
      continue;
    }
    if (path.contains("base.apk")) {
      return std::string(path);
    }
    if (!fallback.has_value()) {
      fallback = std::string(path);
    }
  }
  return fallback;
}

/// The APK path read from the process's memory map.
[[nodiscard]] std::optional<std::string> apk_from_maps() {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,misc-include-cleaner): open is a libc variadic function, and its
  // flags come from the included <fcntl.h>.
  const int descriptor = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return std::nullopt;
  }
  std::string content;
  std::vector<char> buffer(8192);
  for (;;) {
    const ssize_t count = read(descriptor, buffer.data(), buffer.size());
    if (count < 0) {
      close(descriptor);
      return std::nullopt;
    }
    if (count == 0) {
      break;
    }
    content.append(buffer.data(), static_cast<std::size_t>(count));
  }
  close(descriptor);
  return apk_in_maps(content);
}

}  // namespace

std::optional<std::string> self_apk_path() {
  const std::optional<std::string> path = library_path();
  if (path.has_value()) {
    const std::size_t bang = path->find("!/");
    if (bang != std::string::npos) {
      return path->substr(0, bang);
    }
    const std::optional<std::string> beside = apk_beside_library(*path);
    if (beside.has_value()) {
      return beside;
    }
  }
  return apk_from_maps();
}

std::optional<std::string> self_library_dir() {
  const std::optional<std::string> path = library_path();
  if (!path.has_value()) {
    return std::nullopt;
  }
  const std::size_t slash = path->find_last_of('/');
  if (slash == std::string::npos) {
    return std::nullopt;
  }
  return path->substr(0, slash);
}

}  // namespace rasp::android::apk
