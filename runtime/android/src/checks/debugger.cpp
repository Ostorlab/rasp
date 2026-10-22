/// The Android debugger checks: the tracer probe, and its unsupported result off Android.

#include "checks/debugger.h"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "rasp/observation.h"
#include "util/read_file.h"

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

}  // namespace

Observation observe_tracer_pid(std::string_view status_path) {
  const std::optional<std::string> status = util::read_file(status_path, kMaxStatusSize);
  if (!status) {
    return failed(kTracerPidSignal, kTracerPidSource);
  }
  const std::optional<std::int64_t> pid = parse_tracer_pid(*status);
  if (!pid) {
    return failed(kTracerPidSignal, kTracerPidSource);
  }
  return observed(kTracerPidSignal, kTracerPidSource, *pid);
}

std::vector<Observation> debugger() {
  if (!kOnAndroid) {
    return {unsupported(kTracerPidSignal, kTracerPidSource)};
  }
  return {observe_tracer_pid(kStatusPath)};
}

}  // namespace rasp::android::checks
