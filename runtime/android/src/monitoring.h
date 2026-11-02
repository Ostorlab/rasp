/// start_monitoring: runs the checks and the plugins every minute, on the runtime's own thread.

#pragma once

namespace rasp::android {

/// Starts the thread that runs the checks, and returns at once.
///
/// The thread first initialises the plugins compiled into the runtime, with the runtime's config, which the packer
/// wrote into librasp.so.
/// Then it runs the built-in checks of the groups the config enables, every group when the config lists none, and the
/// plugins, and runs them again every 60 seconds. A development build logs each observation.
///
/// Nothing is checked when the thread can't be started. Otherwise the thread never ends: it runs until the process
/// exits. The thread is detached: the app never waits for it, and the app may exit at any moment while it runs.
void start_monitoring() noexcept;

}  // namespace rasp::android
