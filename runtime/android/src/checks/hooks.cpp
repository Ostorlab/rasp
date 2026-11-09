/// The Android hooking checks: the memory-map probe, and its unsupported result off Android. The list of
/// instrumentation markers draws on the names Frida, Substrate and Xposed map their code under.

#include "checks/hooks.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <dirent.h>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/read_file.h"

namespace rasp::android::checks {

namespace {

using rasp::util::read_file;

#ifdef __ANDROID__
/// Whether this build runs on Android, the only place the probe means anything.
constexpr bool kOnAndroid = true;
#else
/// Whether this build runs on Android, the only place the probe means anything.
constexpr bool kOnAndroid = false;
#endif

/// The signal of the probe that reports mappings of a known instrumentation framework.
constexpr std::string_view kMapsHitsSignal = "hook.maps_hits";
/// The signal of the probe that reports writable-executable mappings.
constexpr std::string_view kRwxRegionsSignal = "hook.rwx_regions";
/// The signal of the thread-name probe.
constexpr std::string_view kThreadsSignal = "hook.threads";
/// The source of both memory-map probes.
constexpr std::string_view kMapsSource = "proc_maps";
/// The source of the thread-name probe.
constexpr std::string_view kThreadsSource = "proc_task";
/// The thread names a hooking framework gives its own threads. Frida's GUM runtime names its JavaScript loop
/// `gum-js-loop`, and its GLib integration names the main loop `gmain`, the D-Bus thread `gdbus` and the worker
/// pool `pool-frida`. A framework that renames its threads is caught by its memory mapping instead.
constexpr auto kThreadMarkers = std::to_array<std::string_view>({
    "gum-js-loop",
    "gmain",
    "gdbus",
    "pool-frida",
});

/// The app's memory map.
constexpr std::string_view kMapsPath = "/proc/self/maps";
/// The app's thread list.
constexpr std::string_view kTaskPath = "/proc/self/task";
/// The largest memory map read. A real one is a few hundred KiB.
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;
/// The most lines reported in each list.
constexpr std::size_t kMaxLines = 32;
/// The most thread names reported.
constexpr std::size_t kMaxThreadNames = 16;
/// The largest thread-name file read, the `comm` file of one thread.
constexpr std::size_t kMaxCommSize = 32;

/// The text that marks a mapping made by a known instrumentation or hooking framework, matched anywhere in the line.
/// Frida maps its agent and gadget, Substrate and Xposed map their own libraries, and a gadget is often injected
/// through a `re.frida` or `libgadget` name. These catch a framework that keeps its default names; one rebuilt to
/// rename itself is caught instead by the writable-executable and prologue probes.
constexpr auto kFrameworkMarkers = std::to_array<std::string_view>({
    "frida",
    "gadget",
    "gum-js-loop",
    "substrate",
    "xposed",
    "lsposed",
    "riru",
    "zygisk",
    "magisk",
});

/// The permissions field of a memory-map line, the second space-separated field, or empty when the line has none.
[[nodiscard]] std::string_view permissions_of(std::string_view line) {
  const std::size_t start = line.find(' ');
  if (start == std::string_view::npos) {
    return {};
  }
  const std::string_view rest = line.substr(start + 1);
  const std::size_t end = rest.find(' ');
  return rest.substr(0, std::min(end, rest.size()));
}

/// Whether `line` is a mapping that names a known instrumentation framework.
[[nodiscard]] bool names_framework(std::string_view line) {
  std::string lowered(line);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  return std::ranges::any_of(kFrameworkMarkers,
                             [&lowered](std::string_view marker) { return lowered.contains(marker); });
}

/// Whether `line` maps memory that is both writable and executable.
[[nodiscard]] bool writable_executable(std::string_view line) {
  const std::string_view perms = permissions_of(line);
  return perms.size() >= 3 && perms[1] == 'w' && perms[2] == 'x';
}

/// The first kMaxLines lines of `maps` that `matches`, without their line breaks.
[[nodiscard]] std::vector<std::string> matching_lines(std::string_view maps, bool (*matches)(std::string_view line)) {
  std::vector<std::string> lines;
  for (const auto piece : std::views::split(maps, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    if (line.empty() || !matches(line)) {
      continue;
    }
    lines.emplace_back(line);
    if (lines.size() == kMaxLines) {
      break;
    }
  }
  return lines;
}

}  // namespace

std::vector<Observation> observe_maps(std::string_view maps_path) {
  const std::optional<std::string> maps = read_file(maps_path, kMaxMapsSize);
  if (!maps) {
    return {failed(kMapsHitsSignal, kMapsSource), failed(kRwxRegionsSignal, kMapsSource)};
  }
  return {
      observed(kMapsHitsSignal, kMapsSource, matching_lines(*maps, names_framework)),
      observed(kRwxRegionsSignal, kMapsSource, matching_lines(*maps, writable_executable)),
  };
}

/// Whether the thread name `name` is one a hooking framework gives its threads.
[[nodiscard]] bool is_framework_thread(std::string_view name) {
  return std::ranges::any_of(kThreadMarkers, [&name](std::string_view marker) { return name.contains(marker); });
}

std::vector<Observation> observe_threads(std::string_view task_path) {
  std::vector<std::string> hits;
  // NOLINTNEXTLINE(concurrency-mt-unsafe): the thread list is read once, on the monitoring thread.
  ::DIR* const directory = opendir(std::string(task_path).c_str());
  if (directory == nullptr) {
    return {failed(kThreadsSignal, kThreadsSource)};
  }
  while (const ::dirent* const entry = readdir(directory)) {
    const std::string comm = std::string(task_path) + "/" + entry->d_name + "/comm";
    const std::optional<std::string> name = read_file(comm, kMaxCommSize);
    if (!name) {
      continue;
    }
    const std::string_view trimmed =
        std::string_view(*name).substr(0, std::min<std::size_t>(name->size(), name->find_last_not_of("\n") + 1));
    if (is_framework_thread(trimmed)) {
      hits.emplace_back(trimmed);
    }
  }
  static_cast<void>(closedir(directory));
  std::ranges::sort(hits);
  hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
  if (hits.size() > kMaxThreadNames) {
    hits.resize(kMaxThreadNames);
  }
  return {observed(kThreadsSignal, kThreadsSource, std::move(hits))};
}

std::vector<Observation> hooks() {
  if (!kOnAndroid) {
    return {unsupported(kMapsHitsSignal, kMapsSource), unsupported(kRwxRegionsSignal, kMapsSource),
            unsupported(kThreadsSignal, kThreadsSource)};
  }
  std::vector<Observation> observations = observe_maps(kMapsPath);
  std::ranges::move(observe_threads(kTaskPath), std::back_inserter(observations));
  return observations;
}

}  // namespace rasp::android::checks
