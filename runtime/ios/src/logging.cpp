#include "rasp/logging.h"

#include <os/log.h>
#include <string>
#include <string_view>

namespace rasp {

void log(std::string_view message) noexcept {
  const std::string line(message);
  os_log(OS_LOG_DEFAULT, "RaspRuntime %{public}s", line.c_str());
}

}  // namespace rasp
