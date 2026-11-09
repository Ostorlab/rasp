/// start_monitoring: runs the checks and the plugins again and again, at random intervals, on the runtime's own
/// thread.

#pragma once

#include <string>

namespace rasp::ios {

/// Starts the thread that runs the checks, and returns at once.
///
/// It must be called while the runtime loads, on the app's main thread, before the app's own code runs. The thread
/// reports `inserted_libraries` on every pass and never reads the environment itself.
///
/// The thread first initialises the plugins compiled into the runtime, with the runtime's config, which the packer
/// wrote into the framework's binary, and the install id it keeps in the sandbox's Library/Application Support,
/// excluded from backups. Then it runs the built-in checks of the groups the config enables, and the plugins, and
/// runs them again after a random wait from check_interval, 30 to 90 seconds, drawn again before each wait. No group
/// runs when the config enables none. A development build logs each observation and each wait.
///
/// The thread beats the heartbeat of monitor_heartbeat when it starts, and before and after each run. Each run also
/// reports the heartbeat's integ.monitor_alive observation with the built-in checks'.
///
/// When the built-in checks or the heartbeat detect something, a release build ends the process a few seconds later,
/// through panic_on_detection. The plugins still receive that run's observations in the meantime, but the end doesn't
/// wait for them. A development build never ends the process: it logs what would have ended it.
///
/// Nothing is checked when the thread can't be started, and the heartbeat then never beats. Otherwise the thread never
/// ends: it runs until the process exits, and iOS suspends it while the app is in the background. The thread is
/// detached: the app never waits for it, and the app may exit at any moment while it runs.
///
/// @param inserted_libraries The value of `DYLD_INSERT_LIBRARIES` when the runtime loaded, as
/// checks::read_inserted_libraries returns it, read once while the runtime loads.
void start_monitoring() noexcept;

}  // namespace rasp::ios
