/// start_monitoring: runs the checks and the plugins every minute, on the runtime's own thread.

#pragma once

namespace rasp::ios {

/// Starts the thread that runs the checks, and returns at once.
///
/// It must be called while the runtime loads, on the app's main thread, before the app's own code runs. It first reads
/// the value of `DYLD_INSERT_LIBRARIES` from the app's environment, once, and hands the copy to the thread, which
/// reports it on every pass and never reads the environment itself.
///
/// The thread runs the built-in checks and the plugins compiled into the runtime, then runs them again every 60
/// seconds. A development build logs each observation.
///
/// Nothing is checked when the thread can't be started. Otherwise the thread never ends: it runs until the process
/// exits, and iOS suspends it while the app is in the background. The thread is detached: the app never waits for it,
/// and the app may exit at any moment while it runs.
void start_monitoring() noexcept;

}  // namespace rasp::ios
