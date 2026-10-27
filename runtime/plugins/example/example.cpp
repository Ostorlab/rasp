/// The example plugin. It reports the size of its config, and from its second run on, how many observations the
/// previous run held.

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins::example {

namespace {

/// What the plugin remembers between runs.
struct Memory {
  /// The size of the plugin's config, in bytes.
  std::int64_t config_size = 0;
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

/// Remembers the size of the config, and accepts every config.
///
/// @param config The plugin's config.
/// @return `true`.
[[nodiscard]] bool accept(std::string_view config) {
  memory().config_size = static_cast<std::int64_t>(config.size());
  return true;
}

/// Reports the size of the config.
///
/// @return One example.config_size observation read through init: the size in bytes.
[[nodiscard]] std::vector<Observation> config_size() {
  return {observed("example.config_size", "init", memory().config_size)};
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
constexpr std::array<Check, 2> kChecks{config_size, seen};

}  // namespace

/// The example plugin.
extern constexpr Plugin kPlugin{.name = "example", .init = accept, .checks = kChecks, .on_observations = count};

}  // namespace rasp::plugins::example
