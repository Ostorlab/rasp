/// The Android debugger checks: the tracer probe through libc and through direct system calls, the Java debugger probe
/// through JNI, and their unsupported results off Android.

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
#include "rasp/util/read_file.h"
#include "util/direct_syscall.h"

#ifdef __ANDROID__
#include <jni.h>
#endif

namespace rasp::android::checks {

namespace {

/// The signal of the tracer probe.
constexpr std::string_view kTracerPidSignal = "dbg.tracer_pid";
/// The source of the tracer probe that reads the status file through the libc file functions.
constexpr std::string_view kTracerPidSource = "proc_status";
/// The source of the tracer probe that reads the status file through direct system calls.
constexpr std::string_view kTracerPidDirectSource = "proc_status_syscall";

/// The signal of the Java debugger probe.
constexpr std::string_view kJavaDebuggerSignal = "dbg.java_debugger";
/// The source of the Java debugger probe.
constexpr std::string_view kJavaDebuggerSource = "is_debugger_connected";

#ifdef __ANDROID__
/// The app's status file. Only debugger() reads it, on a device, so it is guarded; observe_tracer_pid takes the path
/// from its caller.
constexpr std::string_view kStatusPath = "/proc/self/status";
#endif
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

/// The dbg.tracer_pid observation through `source` of `status`, the status file as that source read it, or nothing
/// when it couldn't read it.
[[nodiscard]] Observation tracer_pid_from(const std::optional<std::string>& status, std::string_view source) {
  if (!status) {
    return failed(kTracerPidSignal, source);
  }
  const std::optional<std::int64_t> pid = parse_tracer_pid(*status);
  if (!pid) {
    return failed(kTracerPidSignal, source);
  }
  return observed(kTracerPidSignal, source, *pid);
}

#ifdef __ANDROID__
/// Asks the Java VM, through `env`, what `android.os.Debug.isDebuggerConnected` returns, or gives nothing when a JNI
/// call fails. It clears any exception a call leaves.
[[nodiscard]] std::optional<bool> ask_debugger_connected(JNIEnv* env) {
  jclass debug = env->FindClass("android/os/Debug");
  if (debug == nullptr) {
    env->ExceptionClear();
    return std::nullopt;
  }
  std::optional<bool> connected;
  jmethodID method = env->GetStaticMethodID(debug, "isDebuggerConnected", "()Z");
  if (method != nullptr) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): the JNI call methods are variadic by design.
    const jboolean answer = env->CallStaticBooleanMethod(debug, method);
    if (env->ExceptionCheck() == JNI_FALSE) {
      connected = answer == JNI_TRUE;
    }
  }
  env->ExceptionClear();
  env->DeleteLocalRef(debug);
  return connected;
}

/// Asks the app's Java VM whether a Java debugger is connected, or gives nothing when there is no VM or a JNI call
/// fails. A thread that isn't attached to the VM is attached as a daemon for the call and detached after it.
[[nodiscard]] std::optional<bool> java_debugger_connected() {
  JavaVM* vm = nullptr;
  jsize count = 0;
  if (JNI_GetCreatedJavaVMs(&vm, 1, &count) != JNI_OK || count < 1 || vm == nullptr) {
    return std::nullopt;
  }
  void* attached_env = nullptr;
  const jint state = vm->GetEnv(&attached_env, JNI_VERSION_1_6);
  if (state == JNI_OK) {
    return ask_debugger_connected(static_cast<JNIEnv*>(attached_env));
  }
  if (state != JNI_EDETACHED) {
    return std::nullopt;
  }
  JNIEnv* env = nullptr;
  if (vm->AttachCurrentThreadAsDaemon(&env, nullptr) != JNI_OK || env == nullptr) {
    return std::nullopt;
  }
  const std::optional<bool> connected = ask_debugger_connected(env);
  if (vm->DetachCurrentThread() != JNI_OK) {
    return std::nullopt;
  }
  return connected;
}
#endif

}  // namespace

std::vector<Observation> observe_tracer_pid(std::string_view status_path) {
  return {
      tracer_pid_from(rasp::util::read_file(status_path, kMaxStatusSize), kTracerPidSource),
      tracer_pid_from(util::read_file_direct(status_path, kMaxStatusSize), kTracerPidDirectSource),
  };
}

Observation observe_java_debugger(std::optional<bool> connected) {
  if (!connected) {
    return failed(kJavaDebuggerSignal, kJavaDebuggerSource);
  }
  return observed(kJavaDebuggerSignal, kJavaDebuggerSource, *connected);
}

std::vector<Observation> debugger() {
#ifdef __ANDROID__
  std::vector<Observation> observations = observe_tracer_pid(kStatusPath);
  observations.push_back(observe_java_debugger(java_debugger_connected()));
  return observations;
#else
  return {
      unsupported(kTracerPidSignal, kTracerPidSource),
      unsupported(kTracerPidSignal, kTracerPidDirectSource),
      unsupported(kJavaDebuggerSignal, kJavaDebuggerSource),
  };
#endif
}

}  // namespace rasp::android::checks
