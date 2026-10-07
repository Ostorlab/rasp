#include <os/log.h>

#include <string>

#include "rasp/version.h"

namespace {

__attribute__((constructor)) void rasp_start() {
  const std::string version(rasp::kRuntimeVersion);
  os_log(OS_LOG_DEFAULT, "RaspRuntime %{public}s loaded", version.c_str());
}

}  // namespace
