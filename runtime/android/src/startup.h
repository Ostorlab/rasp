/// run_startup_checks: the checks that run while librasp.so loads, before anything else of the runtime.

#pragma once

namespace rasp::android {

/// Runs the start-up checks, and arms a panic when they detect something.
///
/// It must be called while librasp.so loads, on the app's main thread, before the monitoring thread starts and before
/// the on-demand loader is installed, so it finishes before the first business class can be served. It runs, on the
/// calling thread, the debugger, hooking, self-integrity, root and emulator checks, which together take a few
/// milliseconds, use no network and never call fork. When they detect something, a release build ends the process a few
/// seconds later, through panic_on_detection. A development build logs each observation and how long the checks took,
/// and logs what would have ended the process instead.
void run_startup_checks() noexcept;

}  // namespace rasp::android
