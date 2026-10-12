/// start_reporting: sends the launch's observations to the ADR server, on the runtime's own thread.

#pragma once

#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android {

/// Starts the thread that reports the launch's observations to the ADR server, and returns at once.
///
/// The thread loads the install id from `directory`, makes a new session id, and sends the observations as the
/// session's first batch to the ADR server (kServerHost and kServerPath), through TlsTransport. Then it ends. It never
/// calls Java, so it doesn't attach itself to the JVM.
///
/// Nothing is sent when `build_id` is empty because the app wasn't packed, or when the thread can't be started. The
/// thread is detached: the app never waits for it, and the app may exit while it runs.
///
/// @param build_id The id the packer gave the protected build, from the app's `assets/rasp/config.json`.
/// @param directory The directory that keeps the install id from one launch to the next. When it is empty, the
/// install id is a new random one, for this launch only.
/// @param observations What the checks observed at launch.
void start_reporting(std::string build_id, std::string directory, std::vector<Observation> observations) noexcept;

}  // namespace rasp::android
