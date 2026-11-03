/// The Android hooking checks: the memory-map probe, the thread probe, and their unsupported results off Android. The
/// list of instrumentation markers draws on the names Frida, Substrate and Xposed map their code under, and the
/// thread markers on the names of the threads Frida's agent starts.

#include "checks/hooks.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
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
/// The source of both memory-map probes.
constexpr std::string_view kMapsSource = "proc_maps";
/// The signal of the probe that reports the app's threads named like an instrumentation framework's.
constexpr std::string_view kThreadsSignal = "hook.threads";
/// The source of the thread probe.
constexpr std::string_view kTaskSource = "proc_task";

/// The app's memory map.
constexpr std::string_view kMapsPath = "/proc/self/maps";
/// The folder that holds one folder per thread of the app.
constexpr std::string_view kTaskPath = "/proc/self/task";
/// The largest thread name read. The kernel keeps at most 15 characters and a line break.
constexpr std::size_t kMaxThreadNameSize = 64;
/// The most threads looked at. An app has a few hundred at most.
constexpr std::size_t kMaxThreads = 4096;
/// The largest memory map read. A real one is a few hundred KiB.
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;
/// The most lines reported in each list.
constexpr std::size_t kMaxLines = 32;

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

/// The text that marks a thread started by Frida's agent, matched anywhere in the thread's name: its JavaScript thread,
/// `gum-js-loop`, and its worker pool, `pool-frida`. The kernel keeps only a thread's first 15 characters, which these
/// fit in.
constexpr auto kThreadMarkers = std::to_array<std::string_view>({
    "gum-js-loop",
    "frida",
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

/// Whether `text` contains one of `markers`, ignoring case.
///
/// @param text The text to look in.
/// @param markers The lowercase markers.
/// @return `true` when one of them is in `text`.
[[nodiscard]] bool contains_marker(std::string_view text, std::span<const std::string_view> markers) {
  std::string lowered(text);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  return std::ranges::any_of(markers, [&lowered](std::string_view marker) { return lowered.contains(marker); });
}

/// Whether `line` is a mapping that names a known instrumentation framework.
[[nodiscard]] bool names_framework(std::string_view line) { return contains_marker(line, kFrameworkMarkers); }

/// The name of the thread whose folder is `thread_folder`, without its line break.
///
/// @param thread_folder The thread's folder, such as `/proc/self/task/1234`.
/// @return The name. Nothing when it can't be read, such as when the thread ended after the folder was listed.
[[nodiscard]] std::optional<std::string> thread_name(const std::filesystem::path& thread_folder) {
  std::optional<std::string> name = read_file((thread_folder / "comm").string(), kMaxThreadNameSize);
  if (name && name->ends_with('\n')) {
    name->pop_back();
  }
  return name;
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

Observation observe_threads(std::string_view task_path) {
  std::error_code error;
  std::filesystem::directory_iterator iterator(std::filesystem::path(task_path), error);
  if (error) {
    return failed(kThreadsSignal, kTaskSource);
  }
  const std::filesystem::directory_iterator end;
  std::set<std::string> names;
  std::size_t threads = 0;
  while (iterator != end && threads < kMaxThreads && names.size() < kMaxLines) {
    ++threads;
    const std::optional<std::string> name = thread_name(iterator->path());
    if (name && contains_marker(*name, kThreadMarkers)) {
      names.insert(*name);
    }
    iterator.increment(error);
    if (error) {
      return failed(kThreadsSignal, kTaskSource);
    }
  }
  return observed(kThreadsSignal, kTaskSource, std::vector<std::string>{names.begin(), names.end()});
}

std::vector<Observation> hooks() {
  if (!kOnAndroid) {
    return {
        unsupported(kMapsHitsSignal, kMapsSource),
        unsupported(kRwxRegionsSignal, kMapsSource),
        unsupported(kThreadsSignal, kTaskSource),
    };
  }
  std::vector<Observation> observations = observe_maps(kMapsPath);
  observations.push_back(observe_threads(kTaskPath));
  return observations;
}

}  // namespace rasp::android::checks
