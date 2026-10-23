/// The iOS hooking checks: the loaded-image probe, and its unsupported result off a physical device. The markers and
/// folders draw on the names and places Frida, Cycript, Substrate, the tweak loaders and SSL Kill Switch install their
/// libraries under, on rootful and rootless jailbreaks.

#include "checks/hooks.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <cstdint>
#include <mach-o/dyld.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the probe that reports images of a known instrumentation or hooking framework.
constexpr std::string_view kMapsHitsSignal = "hook.maps_hits";
/// The source of the probe.
constexpr std::string_view kDyldSource = "dyld";

#ifdef __APPLE__
/// The most images the probe reads from dyld's list. A real app loads far fewer.
constexpr std::uint32_t kMaxImages = 4096;
#endif

/// The most paths reported in the list.
constexpr std::size_t kMaxPaths = 32;

/// The text that marks the file name of an image of a known instrumentation or hooking framework, in lowercase, matched
/// anywhere in the last component of the path without regard to case. Each one is part of the name of a file these
/// frameworks install, not a whole word that an app's own framework could also use. It covers Frida's agent and gadget
/// (`frida-agent.dylib`, `frida-gadget.dylib` and `FridaGadget.dylib`), Cycript, Substrate (`CydiaSubstrate`,
/// `MobileSubstrate.dylib`, `libsubstrate.dylib` and its loader, inserter and bootstrap), the hooking libraries that
/// replace it (Substitute, libhooker with libblackjack, and ElleKit), the TweakInject and TweakLoader tweak loaders,
/// and SSL Kill Switch.
constexpr auto kFrameworkMarkers = std::to_array<std::string_view>({
    "frida-agent",
    "frida-gadget",
    "fridagadget",
    "libcycript",
    "cydiasubstrate",
    "mobilesubstrate",
    "libsubstrate",
    "substrateloader",
    "substrateinserter",
    "substratebootstrap",
    "libsubstitute",
    "libhooker",
    "libblackjack",
    "libellekit",
    "tweakinject",
    "tweakloader",
    "sslkillswitch",
});

/// The folders that only hold the files of a tweak loader or of the tweaks it loads, in lowercase, relative to the root
/// of the jailbreak and matched at the start of the path without regard to case. An image in one of them is reported
/// whatever its file name: Substrate's `DynamicLibraries` folder, the `TweakInject` folder of the loaders that replace
/// it, ElleKit's own folder, which holds its `libinjector.dylib` loader, and Substitute's tweak and helper folders.
constexpr auto kTweakFolders = std::to_array<std::string_view>({
    "/library/mobilesubstrate/dynamiclibraries/",
    "/usr/lib/tweakinject/",
    "/usr/lib/ellekit/",
    "/library/substitute/dynamiclibraries/",
    "/library/substitute/helpers/",
});

/// The roots a rootless jailbreak installs its files under, in lowercase, each followed by a slash. `/var/jb` is the
/// path jailbreaks give their files, and `/private/var/jb` is the same folder as dyld names it, since `/var` is a link
/// to `/private/var`.
constexpr auto kJailbreakRoots = std::to_array<std::string_view>({
    "/var/jb/",
    "/private/var/jb/",
});

/// The start of the real folder that `/var/jb` links to on a rootless jailbreak, in lowercase. dyld names an image by
/// its real path, with every link resolved, such as
/// `/private/preboot/HASH/dopamine-ID/procursus/usr/lib/TweakInject/Tweak.dylib`.
constexpr std::string_view kPrebootFolder = "/private/preboot/";

/// The folder inside kPrebootFolder that is the root of a rootless jailbreak, in lowercase.
constexpr std::string_view kProcursusFolder = "/procursus/";

/// Returns `text` in lowercase.
///
/// @param text The text to convert.
/// @return A copy of `text` with every ASCII letter in lowercase.
[[nodiscard]] std::string lowercase(std::string_view text) {
  std::string lowered(text);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  return lowered;
}

/// Returns `path` relative to the root of the jailbreak that installed it.
///
/// A path under `/var/jb/` or `/private/var/jb/` loses that root. A path under kPrebootFolder loses everything up to
/// its first kProcursusFolder. Any other path, the path of a rootful jailbreak's file among them, is returned as it is.
///
/// @param path The lowercase path of an image.
/// @return The part of `path` that starts at the slash after the jailbreak's root, or `path` itself.
[[nodiscard]] std::string_view without_jailbreak_root(std::string_view path) {
  for (const std::string_view root : kJailbreakRoots) {
    if (path.starts_with(root)) {
      return path.substr(root.size() - 1);
    }
  }
  if (path.starts_with(kPrebootFolder)) {
    const std::size_t procursus = path.find(kProcursusFolder, kPrebootFolder.size() - 1);
    if (procursus != std::string_view::npos) {
      return path.substr(procursus + kProcursusFolder.size() - 1);
    }
  }
  return path;
}

/// Returns the file name of `path`, the part after its last slash.
///
/// @param path The path of an image.
/// @return The last component of `path`, or `path` itself when it has no slash.
[[nodiscard]] std::string_view file_name(std::string_view path) {
  const std::size_t slash = path.rfind('/');
  return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

/// Whether `path` is the path of an image that names a known instrumentation or hooking framework.
///
/// It does when the image is in one of kTweakFolders, under any jailbreak root, or when its file name contains one of
/// kFrameworkMarkers. Both are matched without regard to case. The folders of the path above the file, such as the
/// name of the app's bundle, are never matched against the markers.
///
/// @param path The path of an image.
/// @return Whether the image is a known framework's.
[[nodiscard]] bool names_framework(std::string_view path) {
  const std::string lowered = lowercase(path);
  const std::string_view relative = without_jailbreak_root(lowered);
  if (std::ranges::any_of(kTweakFolders,
                          [relative](std::string_view folder) { return relative.starts_with(folder); })) {
    return true;
  }
  const std::string_view name = file_name(lowered);
  return std::ranges::any_of(kFrameworkMarkers, [name](std::string_view marker) { return name.contains(marker); });
}

}  // namespace

Observation observe_images(std::span<const std::string> image_paths) {
  std::vector<std::string> paths;
  for (const std::string& path : image_paths) {
    if (!names_framework(path)) {
      continue;
    }
    paths.push_back(path);
    if (paths.size() == kMaxPaths) {
      break;
    }
  }
  return observed(kMapsHitsSignal, kDyldSource, std::move(paths));
}

Observation observe_loaded_images() {
#ifdef __APPLE__
  const std::uint32_t count = _dyld_image_count();
  if (count > kMaxImages) {
    return failed(kMapsHitsSignal, kDyldSource);
  }
  std::vector<std::string> images;
  images.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    const char* const name = _dyld_get_image_name(index);
    if (name != nullptr) {
      images.emplace_back(name);
    }
  }
  return observe_images(images);
#else
  return unsupported(kMapsHitsSignal, kDyldSource);
#endif
}

std::vector<Observation> hooks() {
  if (!kPhysicalDevice) {
    return {unsupported(kMapsHitsSignal, kDyldSource)};
  }
  return {observe_loaded_images()};
}

}  // namespace rasp::ios::checks
