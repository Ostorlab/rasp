/// The load-time entry of librasp.so. A constructor runs when the dynamic linker loads the library, the way iOS starts
/// from a constructor: it starts the runtime's thread, which runs the checks, and returns at once. It does not load the
/// app's code; that is the on-demand loader's job (loader.cpp), which the platform's `JNI_OnLoad` installs moments
/// later. The library exports no `Java_...` entry, only the JVM's `JNI_OnLoad`.

#include <jni.h>
#include <string>

#include "monitoring.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"

namespace {

/// Whether the library is loaded inside a running JVM. On API 31 and newer, `JNI_GetCreatedJavaVMs` is part of the
/// platform's public native API, so a load-time constructor can tell without an exported JNI entry point.
[[nodiscard]] bool running_in_jvm() noexcept {
  JavaVM* vm = nullptr;
  jsize count = 0;
  return JNI_GetCreatedJavaVMs(&vm, 1, &count) == JNI_OK && count > 0;
}

/// Logs the runtime's version in a development build, and starts the thread that runs the checks, without waiting for
/// it, when the dynamic linker loads librasp.so. Outside a Java VM it does nothing.
__attribute__((constructor)) void rasp_start() noexcept {
  if (!running_in_jvm()) {
    return;
  }
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
  }
  rasp::android::start_monitoring();
}

}  // namespace
