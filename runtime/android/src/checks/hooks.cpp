/// The Android hooking checks: the memory-map probe, the thread probe, and their unsupported results off Android. The
/// list of instrumentation markers draws on the names Frida, Substrate and Xposed map their code under, and the
/// thread markers on the names of the threads Frida's agent starts.

#include "checks/hooks.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <iterator>
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
#include "util/direct_syscall.h"
#include "util/proc_text.h"

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
/// The map source using the hookable libc syscall entry.
constexpr std::string_view kMapsDirectSource = "proc_maps_syscall";
/// The signal of the probe that reports the app's threads named like an instrumentation framework's.
constexpr std::string_view kThreadsSignal = "hook.threads";
/// The source of the thread probe.
constexpr std::string_view kTaskSource = "proc_task";

/// The app's memory map.
constexpr std::string_view kMapsPath = "/proc/self/maps";
/// The folder that holds one folder per thread of the app.
constexpr std::string_view kTaskPath = "/proc/self/task";
/// The largest thread name read. The kernel keeps at most 15 characters and a line break.
constexpr std::size_t kMaxThreadNameSize = 16;
/// The most threads looked at. An app has a few hundred at most.
constexpr std::size_t kMaxThreads = 4096;
/// The largest memory map read. A real one is a few hundred KiB.
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;
/// The most lines reported in each list.
constexpr std::size_t kMaxLines = 32;

/// The text that marks a mapping made by a known instrumentation or hooking framework, matched anywhere in the line.
/// Frida maps its agent and gadget, Substrate and Xposed map their own libraries, and a gadget is often injected
/// through a `re.frida` or `libgadget` name. These are heuristic markers; renaming or hiding a framework can evade
/// them, and a matching name alone does not establish instrumentation.
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

/// Whether a maps record has a valid address range, permissions and numeric kernel fields.
[[nodiscard]] bool valid_map_line(std::string_view line) {
  std::string_view rest = line;
  const std::string_view range = util::take_proc_field(rest);
  const std::size_t dash = range.find('-');
  if (dash == std::string_view::npos) {
    return false;
  }
  const auto start = util::proc_number(range.substr(0, dash), 16);
  const auto end = util::proc_number(range.substr(dash + 1), 16);
  const std::string_view perms = util::take_proc_field(rest);
  const auto offset = util::proc_number(util::take_proc_field(rest), 16);
  const std::string_view device = util::take_proc_field(rest);
  const std::size_t colon = device.find(':');
  if (colon == std::string_view::npos) {
    return false;
  }
  const auto major = util::proc_number(device.substr(0, colon), 16);
  const auto minor = util::proc_number(device.substr(colon + 1), 16);
  const auto inode = util::proc_number(util::take_proc_field(rest), 10);
  return start.has_value() && end.has_value() && *start < *end && perms.size() == 4 &&
         (perms[0] == 'r' || perms[0] == '-') && (perms[1] == 'w' || perms[1] == '-') &&
         (perms[2] == 'x' || perms[2] == '-') && (perms[3] == 'p' || perms[3] == 's') && offset.has_value() &&
         major.has_value() && minor.has_value() && inode.has_value();
}

/// The permissions field of an already validated memory-map line.
[[nodiscard]] std::string_view permissions_of(std::string_view line) {
  static_cast<void>(util::take_proc_field(line));
  return util::take_proc_field(line);
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

/// The validated visible kernel name, or nothing for unreadable, incomplete or malformed comm data.
///
/// @param thread_folder The thread's folder, such as `/proc/self/task/1234`.
/// @return One to fifteen non-control bytes, without the required final newline. Kernel truncation is not recoverable.
[[nodiscard]] std::optional<std::string> thread_name(const std::filesystem::path& thread_folder) {
  std::optional<std::string> name = read_file((thread_folder / "comm").string(), kMaxThreadNameSize);
  if (!name.has_value() || name->size() < 2 || !name->ends_with('\n')) {
    return std::nullopt;
  }
  name->pop_back();
  if (std::ranges::any_of(*name, [](unsigned char character) { return character < 32 || character == 127; })) {
    return std::nullopt;
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

std::vector<Observation> observe_maps(std::string_view maps_path, util::SystemCall invoke) {
  std::optional<std::string> maps = read_file(maps_path, kMaxMapsSize);
  std::optional<std::string> direct_maps = util::read_file_direct(maps_path, kMaxMapsSize, invoke);
  if (maps.has_value() && !util::valid_proc_table(*maps, valid_map_line)) {
    maps.reset();
  }
  if (direct_maps.has_value() && !util::valid_proc_table(*direct_maps, valid_map_line)) {
    direct_maps.reset();
  }
  return {
      maps ? observed(kMapsHitsSignal, kMapsSource, matching_lines(*maps, names_framework))
           : failed(kMapsHitsSignal, kMapsSource),
      maps ? observed(kRwxRegionsSignal, kMapsSource, matching_lines(*maps, writable_executable))
           : failed(kRwxRegionsSignal, kMapsSource),
      direct_maps ? observed(kMapsHitsSignal, kMapsDirectSource, matching_lines(*direct_maps, names_framework))
                  : failed(kMapsHitsSignal, kMapsDirectSource),
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
  while (iterator != end) {
    if (threads == kMaxThreads) {
      return failed(kThreadsSignal, kTaskSource);
    }
    ++threads;
    const std::optional<std::string> name = thread_name(iterator->path());
    if (!name.has_value()) {
      return failed(kThreadsSignal, kTaskSource);
    }
    if (contains_marker(*name, kThreadMarkers)) {
      names.insert(*name);
      if (names.size() > kMaxLines) {
        names.erase(std::prev(names.end()));
      }
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
        unsupported(kMapsHitsSignal, kMapsDirectSource),
        unsupported(kThreadsSignal, kTaskSource),
    };
  }
  std::vector<Observation> observations = observe_maps(kMapsPath);
  observations.push_back(observe_threads(kTaskPath));
  return observations;
}

}  // namespace rasp::android::checks
