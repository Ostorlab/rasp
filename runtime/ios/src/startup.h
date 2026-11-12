/// run_startup_checks: the checks that run while the framework loads, before anything else of the runtime.

#pragma once

#include <string_view>

namespace rasp::ios {

/// Runs the start-up checks, and arms a panic when they detect something.
///
/// It must be called while the runtime loads, on the app's main thread, before the monitoring thread starts. It runs,
/// on the calling thread, the debugger checks and the hooking checks of fast_hooks, which together take a few
/// milliseconds, use no network and never call fork. When they detect something, a release build ends the process a
/// few seconds later, through panic_on_detection. A development build logs each observation and how long the checks
/// took, and logs what would have ended the process instead.
///
/// @param inserted_libraries The value of `DYLD_INSERT_LIBRARIES` when the runtime loaded, as
/// checks::read_inserted_libraries returns it.
void run_startup_checks(std::string_view inserted_libraries) noexcept;

}  // namespace rasp::ios
