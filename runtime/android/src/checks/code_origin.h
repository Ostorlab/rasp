/// The Android code-origin checks: executable memory no installed file backs, and the threads that run in it.

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "util/raw_file.h"

namespace rasp::android::checks {

/// The code the process runs besides installed files: the runtime's own image, and the app's package, whose private
/// folders may hold its own native code.
struct OwnCode {
  /// The first address of the runtime's image.
  std::uintptr_t image_start = 0;
  /// The address just past the runtime's image.
  std::uintptr_t image_end = 0;
  std::string_view package;
};

/// Where the code-origin checks read the process.
struct ProcessPaths {
  /// The memory map, `/proc/self/maps` on a device.
  std::string_view maps;
  /// The thread list, `/proc/self/task` on a device, where each thread's name is read.
  std::string_view task;
  /// The main thread's name, `/proc/self/comm` on a device.
  std::string_view comm;
};

/// Runs the code-origin checks and returns what they observed.
///
/// @return hook.exec_origin through proc_maps, then hook.code_origin through thread_stacks; unsupported off Android.
[[nodiscard]] std::vector<Observation> code_origin();

/// Reports the executable mappings that no installed file in an expected place backs, and the threads whose stack holds
/// an address in them.
///
/// @return hook.exec_origin through proc_maps: the lines of those mappings. Then hook.code_origin through
/// thread_stacks: `<thread name> -> <where>` for each such thread. hook.exec_origin has an error status when the map
/// can't be read, and hook.code_origin when the map or no thread stack can be read.
[[nodiscard]] std::vector<Observation> observe_code_origin(const ProcessPaths& paths, const OwnCode& own,
                                                           const rasp::util::ProcessAccess& access = {});

}  // namespace rasp::android::checks
