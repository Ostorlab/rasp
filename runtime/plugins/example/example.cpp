/// The example plugin. It reports the build id the runtime gave its init, how many times its checks have run, and from
/// its second run on, how many observations the previous run held.

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins::example {

namespace {

/// What the plugin remembers between runs.
struct Memory {
  /// The build id the runtime gave `remember`.
  std::string build_id;
  /// How many times `runs` was called.
  std::int64_t runs = 0;
  /// How many observations the last call of `count` received, or -1 before the first call.
  std::int64_t seen = -1;
};

/// The plugin's memory.
///
/// The first call builds it. It is never destroyed, so there is no exit-time destructor.
///
/// @return The memory, which lives as long as the process.
[[nodiscard]] Memory& memory() {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  static auto* const kMemory = new Memory();
  return *kMemory;
}

/// Remembers the build id.
///
/// @param config The runtime's config. Only its build id is read.
void remember(const Config& config, Context& /*context*/) { memory().build_id = config.build_id; }

/// Reports the build id.
///
/// @return One example.build_id observation read through init: the build id the runtime gave the plugin.
[[nodiscard]] std::vector<Observation> build_id(Context& /*context*/) {
  return {observed("example.build_id", "init", memory().build_id)};
}

/// Counts the runs.
///
/// @return One example.runs observation read through counter: how many times the plugin's checks have run, this run
/// included.
[[nodiscard]] std::vector<Observation> runs(Context& /*context*/) {
  ++memory().runs;
  return {observed("example.runs", "counter", memory().runs)};
}

/// Reports how many observations the previous run held.
///
/// @return One example.seen observation read through on_observations: the number of observations. Empty before the
/// first run has ended.
[[nodiscard]] std::vector<Observation> seen(Context& /*context*/) {
  if (memory().seen < 0) {
    return {};
  }
  return {observed("example.seen", "on_observations", memory().seen)};
}

/// Remembers how many observations it received.
///
/// @param observations All the observations. Only their number is read.
void count(std::span<const Observation> observations, Context& /*context*/) {
  memory().seen = static_cast<std::int64_t>(observations.size());
}

/// The plugin's checks.
constexpr std::array<Check, 3> kChecks{build_id, runs, seen};

}  // namespace

/// The example plugin.
extern constexpr Plugin kPlugin{.init = remember, .checks = kChecks, .on_observations = count};

}  // namespace rasp::plugins::example
