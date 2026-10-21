/// The Android log backend: writes development log lines to the system log with __android_log_write. Only
/// development builds compile this file.

#include "rasp/util/logging.h"

#include <android/log.h>
#include <string>
#include <string_view>

namespace rasp {

void log(std::string_view message) noexcept {
  const std::string line(message);
  __android_log_write(ANDROID_LOG_INFO, "RaspRuntime", line.c_str());
}

}  // namespace rasp
