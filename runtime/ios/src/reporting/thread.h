/// start_reporting: sends the launch's observations to the ADR server, on the runtime's own thread.

#pragma once

#include <vector>

#include "rasp/observation.h"

namespace rasp::ios {

/// Starts the thread that reports the launch's observations to the ADR server, and returns at once.
///
/// The thread reads the build id that the packer wrote into the framework's Info.plist, loads the install id from
/// the app's Library/Application Support, makes a new session id, and sends the observations as the session's first
/// batch to the ADR server (kServerHost and kServerPath), through NetworkTransport. Then it ends.
///
/// Nothing is sent when the framework has no build id because it wasn't packed, or when the thread can't be started.
/// The thread is detached: the app never waits for it, and the app may exit while it runs.
///
/// @param observations What the checks observed at launch.
void start_reporting(std::vector<Observation> observations) noexcept;

}  // namespace rasp::ios
