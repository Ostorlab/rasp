/// Finding the APK and the native-library directory of this process, from the library's load path and /proc/self/maps.

#include "apk/location.h"

#include <cstddef>
#include <dlfcn.h>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#include "util/raw_file.h"

namespace rasp::android::apk {

namespace {

/// The largest memory map read. A real /proc/self/maps is a few hundred KiB.
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;

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

/// The apk path a line of /proc/self/maps names: the file-backed mapping under /data/app whose path ends in .apk.
[[nodiscard]] std::optional<std::string_view> apk_in_line(std::string_view line) {
  const std::size_t slash = line.find('/');
  if (slash == std::string_view::npos) {
    return std::nullopt;
  }
  const std::string_view path = line.substr(slash);
  if (!path.ends_with(".apk") || !path.contains("/data/app/")) {
    return std::nullopt;
  }
  return path;
}

/// Whether a line of /proc/self/maps names the app's own base APK.
[[nodiscard]] bool names_base_apk(std::string_view line) {
  const std::optional<std::string_view> path = apk_in_line(line);
  return path.has_value() && path->contains("base.apk");
}

/// Whether a line of /proc/self/maps names any /data/app APK.
[[nodiscard]] bool names_an_apk(std::string_view line) { return apk_in_line(line).has_value(); }

/// The APK path read from the process's memory map. The map is scanned line by line through the direct-system-call
/// reader, not libc, so an interposed libc read function can't answer for the kernel with a forged mapping and steer
/// the package the `owns_package_data` gate checks — and the scan holds one line at a time, so a map larger than any
/// whole read would allocate still locates the store, stopping at the base APK's line when there is one and falling
/// back to the first /data/app APK when there isn't. The shape follows the standard prior art: Chromium's maps
/// reader (https://chromium.googlesource.com/chromium/src/+/main/base/debug/proc_maps_linux.cc) reads
/// /proc/self/maps in a loop because a fixed whole-file cap silently truncates and loses the trailing regions.
[[nodiscard]] std::optional<std::string> apk_from_maps() {
  // The base APK's line first, and the first /data/app APK's when there is none.
  for (const rasp::util::LinePredicate matches : {names_base_apk, names_an_apk}) {
    const std::optional<std::string> line =
        rasp::util::first_proc_line_matching("/proc/self/maps", matches, kMaxMapsSize);
    if (!line.has_value()) {
      continue;
    }
    if (const std::optional<std::string_view> path = apk_in_line(*line)) {
      return std::string(*path);
    }
  }
  return std::nullopt;
}

}  // namespace

std::optional<std::string> self_library_path() {
  Dl_info info = {};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (dladdr(reinterpret_cast<const void*>(&self_library_path), &info) == 0 || info.dli_fname == nullptr) {
    return std::nullopt;
  }
  return std::string(info.dli_fname);
}

std::optional<std::string> self_apk_path() {
  const std::optional<std::string> path = self_library_path();
  if (path.has_value()) {
    const std::size_t bang = path->find("!/");
    if (bang != std::string::npos) {
      std::string apk = path->substr(0, bang);
      // A store split install maps the library from a config split; the app's own APK — the one that
      // holds the class dexes and the fold's asset entries — is the base beside it.
      const std::size_t slash = apk.find_last_of('/');
      if (slash != std::string::npos && apk.substr(slash + 1) != "base.apk") {
        std::string base = apk.substr(0, slash + 1) + "base.apk";
        if (access(base.c_str(), R_OK) == 0) {
          return base;
        }
      }
      return apk;
    }
    const std::optional<std::string> beside = apk_beside_library(*path);
    if (beside.has_value()) {
      return beside;
    }
  }
  return apk_from_maps();
}

std::optional<std::string> self_library_dir() {
  const std::optional<std::string> path = self_library_path();
  if (!path.has_value()) {
    return std::nullopt;
  }
  const std::size_t slash = path->find_last_of('/');
  if (slash == std::string::npos) {
    return std::nullopt;
  }
  return path->substr(0, slash);
}

bool owns_package_data(const std::string& apk_path) {
  const std::size_t name_start = apk_path.find_last_of('/');
  if (name_start == std::string::npos || name_start == 0) {
    return false;
  }
  const std::size_t directory_start = apk_path.find_last_of('/', name_start - 1);
  if (directory_start == std::string::npos) {
    return false;
  }
  const std::string directory = apk_path.substr(directory_start + 1, name_start - directory_start - 1);
  // The package is the directory component before the first dash, the way the schedule's package
  // record parses the same path.
  const std::size_t dash = directory.find('-');
  const std::string package =
      dash == std::string_view::npos ? std::string(directory) : std::string(directory.substr(0, dash));
  if (package.empty() || package.contains('/')) {
    return false;
  }
  const uid_t uid = getuid();
  const std::string data_directory = "/data/user/" + std::to_string(uid / 100000U) + "/" + package;
  struct stat status = {};
  return stat(data_directory.c_str(), &status) == 0 && status.st_uid == uid;
}

}  // namespace rasp::android::apk
