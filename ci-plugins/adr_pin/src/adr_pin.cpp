/// kPlugin, the pin plugin: its one check opens a TLS connection to the host compiled in with RASP_ADR_PIN_HOST, and
/// reports the public keys the host presented and whether the system trusted them. The server compares the keys with
/// the ones the host really uses: other keys mean something in between answered for the host.

#include <array>
#include <chrono>
#include <vector>

#include "handshake.h"
#include "pins.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins::adr_pin {

namespace {

/// How long the check waits for the host's chain. The monitoring thread waits for the check that long at most.
constexpr std::chrono::seconds kTimeout{10};

/// The plugin's init. The host is compiled in, so the plugin needs nothing from the runtime's config.
///
/// @param config The runtime's config, unused.
/// @param context The values the plugins share, unused.
void start(const Config& /*config*/, Context& /*context*/) {}

/// Probes the host.
///
/// @param context The values the plugins share, unused.
/// @return The `mitm.adr_pin` and `mitm.adr_trusted` observations.
[[nodiscard]] std::vector<Observation> probe(Context& /*context*/) {
  return observe(handshake(RASP_ADR_PIN_HOST, kTimeout), sha256);
}

/// The plugin's checks.
constexpr std::array<Check, 1> kChecks{probe};

}  // namespace

/// The pin plugin.
extern constexpr Plugin kPlugin{.init = start, .checks = kChecks};

}  // namespace rasp::plugins::adr_pin
