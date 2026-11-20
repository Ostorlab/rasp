/// The Android debugger checks: the tracer, JDWP thread and debug API probes, and their unsupported results off
/// Android.

#include "checks/debugger.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>

#include "util/jni.h"
#endif

#include "rasp/observation.h"
#include "rasp/util/read_file.h"
#include "util/raw_file.h"

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
/// The source that reads the status file through libc, whose answer is the kernel's unless someone interposes it.
constexpr std::string_view kTracerPidLibcSource = "proc_status_libc";

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
/// The starts of the names ART gives the threads of a JDWP connection.
constexpr std::array<std::string_view, 2> kJdwpThreadPrefixes = {"JDWP", "ADB-JDWP"};

/// The source of the debug API probe.
constexpr std::string_view kDebugApiSource = "debug_api";

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
[[nodiscard]] std::optional<std::string> thread_name(const std::string& thread_path, rasp::util::ProcReader read) {
  std::optional<std::string> name = read(thread_path + "/comm", kMaxThreadNameSize);
  if (name && name->ends_with('\n')) {
    name->pop_back();
  }
  return name;
}

/// Whether the thread folder at `task_path` holds a thread of a JDWP connection, or nothing when the folder can't be
/// read or holds more than kMaxThreads threads. The folder is listed through std::filesystem's directory_iterator —
/// libc opendir/readdir under it — so the listing stays a surface an interposer can answer, for example to hide a
/// JDWP thread's folder, while the per-thread comm reads below go through the direct-system-call reader. Reading the
/// listing through a raw getdents64 would close that; it is the same follow-up observe_threads names.
[[nodiscard]] std::optional<bool> has_jdwp_thread(std::string_view task_path, rasp::util::ProcReader read) {
  std::error_code error;
  std::filesystem::directory_iterator entries(task_path, error);
  std::size_t threads = 0;
  for (; !error && entries != std::filesystem::directory_iterator(); entries.increment(error)) {
    if (!is_thread_id(entries->path().filename().string())) {
      continue;
    }
    ++threads;
    if (threads > kMaxThreads) {
      return std::nullopt;
    }
    const std::optional<std::string> name = thread_name(entries->path().string(), read);
    if (name && is_jdwp_thread(*name)) {
      return true;
    }
  }
  if (error) {
    return std::nullopt;
  }
  return false;
}

#ifdef __ANDROID__
/// The local references a pass of debugger_connected makes.
constexpr jint kLocalFrameCapacity = 4;

/// Calls `android.os.Debug.isDebuggerConnected`, inside a local frame that the caller pops.
///
/// @param env The thread's JNI environment.
/// @return Whether a debugger is connected, or nothing when a call fails or throws.
[[nodiscard]] std::optional<bool> read_debugger_connected(JNIEnv* env) {
  jclass debug = env->FindClass("android/os/Debug");
  if (util::threw(env) || debug == nullptr) {
    return std::nullopt;
  }
  jmethodID is_debugger_connected = env->GetStaticMethodID(debug, "isDebuggerConnected", "()Z");
  if (util::threw(env) || is_debugger_connected == nullptr) {
    return std::nullopt;
  }
  const jboolean connected = env->CallStaticBooleanMethodA(debug, is_debugger_connected, nullptr);
  if (util::threw(env)) {
    return std::nullopt;
  }
  return connected == JNI_TRUE;
}

/// Whether ART says a debugger is connected, through `android.os.Debug.isDebuggerConnected` called on the calling
/// thread, which is attached to the app's Java VM for it. Every local reference is freed.
///
/// @return Whether a debugger is connected, or nothing when the thread can't reach the VM, or a call fails or throws.
[[nodiscard]] std::optional<bool> debugger_connected() {
  JNIEnv* env = util::attached_env();
  if (env == nullptr) {
    return std::nullopt;
  }
  if (env->PushLocalFrame(kLocalFrameCapacity) != JNI_OK) {
    static_cast<void>(util::threw(env));
    return std::nullopt;
  }
  const std::optional<bool> connected = read_debugger_connected(env);
  env->PopLocalFrame(nullptr);
  return connected;
}
#endif

}  // namespace

Observation observe_tracer_pid(std::string_view status_path, rasp::util::ProcReader read) {
  const std::optional<std::string> status = read(status_path, kMaxStatusSize);
  if (!status) {
    return failed(kTracerPidSignal, kTracerPidSource);
  }
  const std::optional<std::int64_t> pid = parse_tracer_pid(*status);
  if (!pid) {
    return failed(kTracerPidSignal, kTracerPidSource);
  }
  return observed(kTracerPidSignal, kTracerPidSource, *pid);
}

Observation observe_tracer_pid_libc(std::string_view status_path) {
  const std::optional<std::string> status = rasp::util::read_file(status_path, kMaxStatusSize);
  if (!status) {
    return failed(kTracerPidSignal, kTracerPidLibcSource);
  }
  const std::optional<std::int64_t> pid = parse_tracer_pid(*status);
  if (!pid) {
    return failed(kTracerPidSignal, kTracerPidLibcSource);
  }
  return observed(kTracerPidSignal, kTracerPidLibcSource, *pid);
}

Observation observe_jdwp_threads(std::string_view task_path, rasp::util::ProcReader read) {
  const std::optional<bool> found = has_jdwp_thread(task_path, read);
  if (!found) {
    return failed(kJavaDebuggerSignal, kJdwpThreadsSource);
  }
  return observed(kJavaDebuggerSignal, kJdwpThreadsSource, *found);
}

Observation observe_debug_api(std::optional<bool> connected) {
  if (!connected) {
    return failed(kJavaDebuggerSignal, kDebugApiSource);
  }
  return observed(kJavaDebuggerSignal, kDebugApiSource, *connected);
}

std::vector<Observation> debugger() {
  if (!kOnAndroid) {
    return {
        unsupported(kTracerPidSignal, kTracerPidSource),
        unsupported(kTracerPidSignal, kTracerPidLibcSource),
        unsupported(kJavaDebuggerSignal, kJdwpThreadsSource),
        unsupported(kJavaDebuggerSignal, kDebugApiSource),
    };
  }
  std::vector<Observation> observations{
      observe_tracer_pid(kStatusPath),
      observe_tracer_pid_libc(kStatusPath),
      observe_jdwp_threads(kTaskPath),
  };
#ifdef __ANDROID__
  observations.push_back(observe_debug_api(debugger_connected()));
#endif
  return observations;
}

}  // namespace rasp::android::checks
