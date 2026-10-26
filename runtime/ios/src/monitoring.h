/// start_monitoring: runs the checks every minute, on the runtime's own thread.

#pragma once

namespace rasp::ios {

/// Starts the thread that runs the checks, and returns at once.
///
/// The thread loads the plugins the packer listed, once. Then it runs a pass: the built-in checks, then the plugins'
/// checks, then gives every plugin the pass's observations. It runs a pass again every 60 seconds. A development
/// build logs each observation.
///
/// Nothing is checked when the thread can't be started. Otherwise the thread never ends: it runs until the process
/// exits, and iOS suspends it while the app is in the background. The thread is detached: the app never waits for it,
/// and the app may exit at any moment while it runs.
void start_monitoring() noexcept;

}  // namespace rasp::ios
