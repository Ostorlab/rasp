/// start_monitoring: runs the checks and the plugins again and again, at random intervals, on the runtime's own
/// thread.

#pragma once

namespace rasp::android {

/// Starts the thread that runs the checks, and returns at once.
///
/// The thread first initialises the plugins compiled into the runtime, with the runtime's config, which the packer
/// wrote into librasp.so, and the install id it keeps in the app's `no_backup` folder. Then it runs the built-in checks
/// of the groups the config enables, and the plugins, and runs them again after a random wait from check_interval, 30
/// to 90 seconds, drawn again before each wait. No group runs when the config has no `checks` list or the list is
/// empty. A development build logs each observation and each wait.
///
/// The thread beats the heartbeat of monitor_heartbeat when it starts, and before and after each run, so code on
/// another thread can tell when it stopped. The thread doesn't observe the heartbeat itself: a thread that stopped
/// can't report it.
///
/// When the built-in checks detect something, a release build ends the process a few seconds later, through
/// panic_on_detection. The plugins still receive that run's observations in the meantime, but the end doesn't wait for
/// them. A development build never ends the process: it logs what would have ended it.
///
/// Nothing is checked when the thread can't be started, and the heartbeat then never beats. Otherwise the thread never
/// ends: it runs until the process exits. The thread is detached: the app never waits for it, and the app may exit at
/// any moment while it runs.
void start_monitoring() noexcept;

}  // namespace rasp::android
