/// The Android debugger checks: the tracer and JDWP thread probes, and their unsupported results off Android.

#include "checks/debugger.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/read_file.h"

namespace rasp::android::checks {

namespace {

#ifdef __ANDROID__
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = true;
#else
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = false;
#endif

/// The signal of the tracer probe.
constexpr std::string_view kTracerPidSignal = "dbg.tracer_pid";
/// The source of the tracer probe.
constexpr std::string_view kTracerPidSource = "proc_status";

/// The app's status file.
constexpr std::string_view kStatusPath = "/proc/self/status";
/// The largest status file read. A real one is about 1.5 KiB.
constexpr std::size_t kMaxStatusSize = std::size_t{64} << 10U;
/// The start of the status line that holds the tracer's process id.
constexpr std::string_view kTracerPidField = "TracerPid:";

/// The signal of the JDWP thread probe.
constexpr std::string_view kJavaDebuggerSignal = "dbg.java_debugger";
/// The source of the JDWP thread probe.
constexpr std::string_view kJdwpThreadsSource = "jdwp_threads";

/// The folder of the app's threads.
constexpr std::string_view kTaskPath = "/proc/self/task";
/// The largest thread name file read. The kernel keeps 15 bytes of a name, and ends the file with a line break.
constexpr std::size_t kMaxThreadNameSize = 64;
/// The most threads read. An app has a few dozen.
constexpr std::size_t kMaxThreads = 4096;
/// The most thread names the observation reports.
constexpr std::size_t kMaxJdwpThreadNames = 16;
/// The starts of the names ART gives the threads of a JDWP connection.
constexpr std::array<std::string_view, 2> kJdwpThreadPrefixes = {"JDWP", "ADB-JDWP"};

/// The process id that `text` holds after optional tabs and spaces, or nothing when it holds anything else.
[[nodiscard]] std::optional<std::int64_t> parse_pid(std::string_view text) {
  const std::size_t start = text.find_first_not_of(" \t");
  if (start == std::string_view::npos) {
    return std::nullopt;
  }
  const std::string_view digits = text.substr(start);
  const char* const end = std::to_address(digits.end());
  std::uint32_t pid = 0;
  const std::from_chars_result result = std::from_chars(std::to_address(digits.begin()), end, pid);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(pid);
}

/// The process id on the first `TracerPid:` line of `status`, or nothing when there is no such line or it doesn't
/// hold a process id.
[[nodiscard]] std::optional<std::int64_t> parse_tracer_pid(std::string_view status) {
  for (const auto piece : std::views::split(status, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    if (line.starts_with(kTracerPidField)) {
      return parse_pid(line.substr(kTracerPidField.size()));
    }
  }
  return std::nullopt;
}

/// Whether `name`, a folder entry under the thread folder, is a thread id: only digits.
[[nodiscard]] bool is_thread_id(std::string_view name) {
  return !name.empty() &&
         std::ranges::all_of(name, [](char character) { return character >= '0' && character <= '9'; });
}

/// Whether `name` is the name of a thread of a JDWP connection.
[[nodiscard]] bool is_jdwp_thread(std::string_view name) {
  return std::ranges::any_of(kJdwpThreadPrefixes, [name](std::string_view prefix) { return name.starts_with(prefix); });
}

/// The name of the thread whose folder is `thread_path`, without the line break that ends it, or nothing when it can't
/// be read.
[[nodiscard]] std::optional<std::string> thread_name(const std::string& thread_path) {
  std::optional<std::string> name = rasp::util::read_file(thread_path + "/comm", kMaxThreadNameSize);
  if (name && name->ends_with('\n')) {
    name->pop_back();
  }
  return name;
}

/// The names of the JDWP threads in the thread folder at `task_path`, the kMaxJdwpThreadNames smallest of them, or
/// nothing when the folder can't be read or holds more than kMaxThreads threads.
[[nodiscard]] std::optional<std::set<std::string>> jdwp_thread_names(std::string_view task_path) {
  std::error_code error;
  std::filesystem::directory_iterator entries(task_path, error);
  std::set<std::string> names;
  std::size_t threads = 0;
  for (; !error && entries != std::filesystem::directory_iterator(); entries.increment(error)) {
    if (!is_thread_id(entries->path().filename().string())) {
      continue;
    }
    ++threads;
    if (threads > kMaxThreads) {
      return std::nullopt;
    }
    const std::optional<std::string> name = thread_name(entries->path().string());
    if (!name || !is_jdwp_thread(*name)) {
      continue;
    }
    names.insert(*name);
    if (names.size() > kMaxJdwpThreadNames) {
      names.erase(std::prev(names.end()));
    }
  }
  if (error) {
    return std::nullopt;
  }
  return names;
}

}  // namespace

Observation observe_tracer_pid(std::string_view status_path) {
  const std::optional<std::string> status = rasp::util::read_file(status_path, kMaxStatusSize);
  if (!status) {
    return failed(kTracerPidSignal, kTracerPidSource);
  }
  const std::optional<std::int64_t> pid = parse_tracer_pid(*status);
  if (!pid) {
    return failed(kTracerPidSignal, kTracerPidSource);
  }
  return observed(kTracerPidSignal, kTracerPidSource, *pid);
}

Observation observe_jdwp_threads(std::string_view task_path) {
  const std::optional<std::set<std::string>> names = jdwp_thread_names(task_path);
  if (!names) {
    return failed(kJavaDebuggerSignal, kJdwpThreadsSource);
  }
  return observed(kJavaDebuggerSignal, kJdwpThreadsSource, std::vector<std::string>{names->begin(), names->end()});
}

std::vector<Observation> debugger() {
  if (!kOnAndroid) {
    return {unsupported(kTracerPidSignal, kTracerPidSource), unsupported(kJavaDebuggerSignal, kJdwpThreadsSource)};
  }
  return {observe_tracer_pid(kStatusPath), observe_jdwp_threads(kTaskPath)};
}

}  // namespace rasp::android::checks
