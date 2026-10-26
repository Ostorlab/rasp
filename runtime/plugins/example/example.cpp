/// The example plugin, written against the C plugin API (rasp/plugin.h). Its one check emits `example.ping`, true, in
/// every pass, and, from the second pass on, `example.seen`: how many observations the previous pass had, which its
/// `on_pass` remembers.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "rasp/plugin.h"

namespace {

/// What the plugin remembers between passes.
struct Memory {
  /// How many observations the last pass had, or -1 before the first pass ends.
  std::int64_t seen = -1;
};

/// The C string of `value`.
///
/// @param value Text that lives as long as the process, such as a string literal.
/// @return The C string that points at it.
[[nodiscard]] constexpr rasp_string text(std::string_view value) {
  return {.data = value.data(), .size = value.size()};
}

/// The plugin's memory, which lives as long as the process.
///
/// @return The memory.
[[nodiscard]] Memory& memory() {
  static Memory value;
  return value;
}

/// The check: emits `example.ping`, true, and, once a pass has ended, `example.seen` with that pass's count.
///
/// @param state The plugin's Memory.
/// @param emit The function that adds an observation to the pass.
/// @param emitter The first argument to pass to `emit`.
void ping(void* state, rasp_emit emit, void* emitter) {
  const rasp_observation alive{
      .signal = text("example.ping"),
      .source = text("constant"),
      .status = RASP_STATUS_OK,
      .value = {.kind = RASP_VALUE_BOOL, .boolean = true},
  };
  emit(emitter, &alive);
  const std::int64_t seen = static_cast<Memory*>(state)->seen;
  if (seen < 0) {
    return;
  }
  const rasp_observation count{
      .signal = text("example.seen"),
      .source = text("on_pass"),
      .status = RASP_STATUS_OK,
      .value = {.kind = RASP_VALUE_INT, .integer = seen},
  };
  emit(emitter, &count);
}

/// Remembers how many observations the pass had.
///
/// @param state The plugin's Memory.
/// @param observations The observations of the pass. Only their number is used.
/// @param count The number of observations.
void remember(void* state, [[maybe_unused]] const rasp_observation* observations, std::size_t count) {
  static_cast<Memory*>(state)->seen = static_cast<std::int64_t>(count);
}

/// The plugin's checks.
constexpr std::array<rasp_check, 1> kChecks{{{.name = text("ping"), .run = ping}}};

}  // namespace

const rasp_plugin* rasp_plugin_init(const rasp_host* host) {
  if (host == nullptr) {
    return nullptr;
  }
  static const rasp_plugin kPlugin{
      .size = sizeof(rasp_plugin),
      .api_version = RASP_PLUGIN_API_VERSION,
      .name = text("example"),
      .version = text("1.0.0"),
      .state = &memory(),
      .checks = kChecks.data(),
      .check_count = kChecks.size(),
      .on_pass = remember,
  };
  return &kPlugin;
}
