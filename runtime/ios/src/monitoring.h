/// start_monitoring: runs the checks and the plugins every minute, on the runtime's own thread.

#pragma once

namespace rasp::ios {

/// Starts the thread that runs the checks, and returns at once.
///
/// It must be called while the runtime loads, on the app's main thread, before the app's own code runs. It first reads
/// the values of `DYLD_INSERT_LIBRARIES` and `HOME` from the app's environment, once, and hands the copies to the
/// thread, which never reads the environment itself.
///
/// The thread first initialises the plugins compiled into the runtime, with the runtime's config, which the packer
/// wrote into the framework's binary, and the install id it keeps in the sandbox's Library/Application Support,
/// excluded from backups. Then it runs the built-in checks of the groups the config enables, and the plugins, and runs
/// them again every 60 seconds. No group runs when the config has no `checks` list or the list is empty. A development
/// build logs each observation.
///
/// Nothing is checked when the thread can't be started. Otherwise the thread never ends: it runs until the process
/// exits, and iOS suspends it while the app is in the background. The thread is detached: the app never waits for it,
/// and the app may exit at any moment while it runs.
void start_monitoring() noexcept;

}  // namespace rasp::ios
