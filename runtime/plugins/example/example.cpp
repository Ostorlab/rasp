/// The example plugin. It reports how many times its checks have run, and from its second run on, how many
/// observations the previous run held.

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins::example {

namespace {

/// What the plugin remembers between runs.
struct Memory {
  /// How many times `runs` was called.
  std::int64_t runs = 0;
  /// How many observations the last call of `count` received, or -1 before the first call.
  std::int64_t seen = -1;
};

/// The plugin's memory.
///
/// @return The memory, which lives as long as the process.
[[nodiscard]] Memory& memory() {
  static Memory value;
  return value;
}

/// Counts the runs.
///
/// @return One example.runs observation read through counter: how many times the plugin's checks have run, this run
/// included.
[[nodiscard]] std::vector<Observation> runs() {
  ++memory().runs;
  return {observed("example.runs", "counter", memory().runs)};
}

/// Reports how many observations the previous run held.
///
/// @return One example.seen observation read through on_observations: the number of observations. Empty before the
/// first run has ended.
[[nodiscard]] std::vector<Observation> seen() {
  if (memory().seen < 0) {
    return {};
  }
  return {observed("example.seen", "on_observations", memory().seen)};
}

/// Remembers how many observations it received.
///
/// @param observations All the observations. Only their number is read.
void count(std::span<const Observation> observations) {
  memory().seen = static_cast<std::int64_t>(observations.size());
}

/// The plugin's checks.
constexpr std::array<Check, 2> kChecks{runs, seen};

}  // namespace

/// The example plugin.
extern constexpr Plugin kPlugin{.checks = kChecks, .on_observations = count};

}  // namespace rasp::plugins::example
