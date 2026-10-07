// Entry point of the runtime on iOS. dyld runs the constructor below when the app loads the
// framework, before the app's main.

#include <os/log.h>

#include <string>

#include "rasp/version.h"

namespace {

__attribute__((constructor)) void rasp_start() {
  const std::string version(rasp::kRuntimeVersion);
  os_log(OS_LOG_DEFAULT, "RaspRuntime %{public}s loaded", version.c_str());
}

}  // namespace
