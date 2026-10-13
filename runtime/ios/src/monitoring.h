/// start_monitoring: runs the checks every minute and reports what changed to the ADR server, on the runtime's own
/// thread.

#pragma once

namespace rasp::ios {

/// Starts the thread that runs the checks and reports their observations to the ADR server, and returns at once.
///
/// The thread reads the build id that the packer wrote into the framework's Info.plist, loads the install id from
/// the app's Library/Application Support, and makes a new session id. Then it runs the checks, sends their
/// observations as the session's first batch to the ADR server (kServerHost and kServerPath) through
/// NetworkTransport, and every 60 seconds runs the checks again and sends, as one batch, only the observations that
/// changed since the last ones sent. A run where nothing changed sends nothing.
///
/// Nothing is checked or sent when the framework has no build id because it wasn't packed, or when the thread can't
/// be started. Otherwise the thread never ends: it runs until the process exits, and iOS suspends it while the app is
/// in the background. The thread is detached: the app never waits for it, and the app may exit at any moment while
/// it runs.
void start_monitoring() noexcept;

}  // namespace rasp::ios
