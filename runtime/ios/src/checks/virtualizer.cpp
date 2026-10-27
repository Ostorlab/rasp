/// The iOS virtualizer check: the container-path and foreign-image probes, and their unsupported results off a physical
/// device.

#include "checks/virtualizer.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFBundle.h>
#include <CoreFoundation/CFURL.h>
#include <TargetConditionals.h>
#include <cstdint>
#include <mach-o/dyld.h>
#include <optional>
#include <sys/syslimits.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the container-path probe.
constexpr std::string_view kContainerSignal = "virt.exec_path";
/// The signal of the foreign-image probe.
constexpr std::string_view kForeignImagesSignal = "virt.foreign_images";
/// The source both probes read through.
constexpr std::string_view kDyldSource = "dyld";

/// The prefix of a genuine install's main executable path: the system's app-container layout.
constexpr std::string_view kContainerPrefix = "/private/var/containers/Bundle/Application/";

/// The system roots whose images are always legitimate: the shared libraries and the OS frameworks.
constexpr auto kSystemRoots = std::to_array<std::string_view>({
    "/usr/lib/",
    "/System/",
});

/// The preboot folder that holds the cryptexes on modern iOS.
constexpr std::string_view kPrebootFolder = "/private/preboot/";
/// The cryptex OS-system segment. dyld reports stock OS frameworks from a cryptex under
/// `/private/preboot/<hash>/Cryptexes/OS/System/...` (and the hashless `/private/preboot/Cryptexes/OS/System/...`),
/// which does not start with `/System/`. A path holding this segment under the preboot folder is a genuine OS image.
constexpr std::string_view kCryptexSystemSegment = "/Cryptexes/OS/System/";

/// Whether `path` is a stock OS image served from a cryptex: it lies under the preboot folder and holds the cryptex
/// OS-system segment. Matching the segment rather than a fixed prefix covers both the hashed and the hashless layouts.
[[nodiscard]] bool is_cryptex_system_image(std::string_view path) {
  return path.starts_with(kPrebootFolder) && path.contains(kCryptexSystemSegment);
}

/// The most foreign image paths the probe reports, so a crafted process can't grow the observation without bound.
constexpr std::size_t kMaxForeignImages = 64;

/// Whether `path` lies under `directory`, matched on a path boundary rather than as a raw string prefix: `path` is the
/// directory itself, or `path` continues with a `/` right after it. This refuses a sibling such as `Example.app.backup`
/// for a directory of `Example.app`, which a raw prefix test would wrongly accept.
[[nodiscard]] bool under_directory(std::string_view path, std::string_view directory) {
  if (!path.starts_with(directory)) {
    return false;
  }
  return path.size() == directory.size() || path[directory.size()] == '/';
}

/// Whether `path` lies within a legitimate root: a system root, a cryptex OS image, or the app's own bundle directory
/// when it is known.
[[nodiscard]] bool within_legitimate_root(std::string_view path, std::string_view bundle_directory) {
  if (!bundle_directory.empty() && under_directory(path, bundle_directory)) {
    return true;
  }
  if (is_cryptex_system_image(path)) {
    return true;
  }
  return std::ranges::any_of(kSystemRoots, [path](std::string_view root) { return path.starts_with(root); });
}

#ifdef __APPLE__
/// Reads the main executable's path with dyld.
///
/// @return The path, or nothing when it doesn't fit in PATH_MAX bytes.
[[nodiscard]] std::optional<std::string> main_executable_path() {
  std::array<char, PATH_MAX> path{};
  auto size = static_cast<std::uint32_t>(path.size());
  if (_NSGetExecutablePath(path.data(), &size) != 0) {
    return std::nullopt;
  }
  return std::string(path.data());
}

/// Reads the file system path of the main bundle's directory.
///
/// The main bundle is owned by CoreFoundation, under the Get rule, so it is not released. Its URL is created here,
/// under the Copy rule, so it is released on every path.
///
/// @return The path, or an empty string when there is no main bundle or URL, or the path doesn't fit in PATH_MAX bytes.
[[nodiscard]] std::string main_bundle_directory() {
  auto* const bundle = CFBundleGetMainBundle();
  if (bundle == nullptr) {
    return {};
  }
  const CFURLRef url = CFBundleCopyBundleURL(bundle);
  if (url == nullptr) {
    return {};
  }
  std::array<std::uint8_t, PATH_MAX> buffer{};
  const bool converted =
      CFURLGetFileSystemRepresentation(url, 1, buffer.data(), static_cast<CFIndex>(buffer.size())) != 0;
  CFRelease(url);
  if (!converted) {
    return {};
  }
  return std::string(buffer.begin(), std::ranges::find(buffer, std::uint8_t{0}));
}

/// The most images the probe reads, a bound a genuine process stays well under.
constexpr std::uint32_t kMaxImages = 4096;

/// Reads the paths of the loaded images with dyld.
///
/// @return The image paths, or nothing when dyld reports more than kMaxImages images.
[[nodiscard]] std::optional<std::vector<std::string>> loaded_image_paths() {
  const std::uint32_t count = _dyld_image_count();
  if (count > kMaxImages) {
    return std::nullopt;
  }
  std::vector<std::string> images;
  images.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    const char* const name = _dyld_get_image_name(index);
    if (name != nullptr) {
      images.emplace_back(name);
    }
  }
  return images;
}
#endif

}  // namespace

Observation observe_container_path(std::string_view exec_path) {
  return observed(kContainerSignal, kDyldSource, !exec_path.starts_with(kContainerPrefix));
}

Observation observe_foreign_images(std::span<const std::string> image_paths, std::string_view bundle_directory) {
  std::vector<std::string> foreign;
  for (const std::string& path : image_paths) {
    if (within_legitimate_root(path, bundle_directory)) {
      continue;
    }
    foreign.push_back(path);
    if (foreign.size() == kMaxForeignImages) {
      break;
    }
  }
  return observed(kForeignImagesSignal, kDyldSource, std::move(foreign));
}

std::vector<Observation> virtualizer() {
  if (!kPhysicalDevice) {
    return {unsupported(kContainerSignal, kDyldSource), unsupported(kForeignImagesSignal, kDyldSource)};
  }
#ifdef __APPLE__
  const std::optional<std::string> exec_path = main_executable_path();
  const Observation container = exec_path ? observe_container_path(*exec_path) : failed(kContainerSignal, kDyldSource);
  const std::optional<std::vector<std::string>> images = loaded_image_paths();
  const Observation foreign =
      images ? observe_foreign_images(*images, main_bundle_directory()) : failed(kForeignImagesSignal, kDyldSource);
  return {container, foreign};
#else
  return {unsupported(kContainerSignal, kDyldSource), unsupported(kForeignImagesSignal, kDyldSource)};
#endif
}

}  // namespace rasp::ios::checks
