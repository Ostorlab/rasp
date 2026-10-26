/// A plugin table written in C11 against rasp/plugin.h, for the host tests: it shows that the header is C and that the
/// runtime reads a table C lays out. Its one check emits `c.list`, a list of two strings, and its on_pass remembers how
/// many observations it was given.

#include <stddef.h>

#include "rasp/plugin.h"

/// How many observations the last pass had.
static size_t seen = 0;

/// Emits `c.list`, the list `a`, `bc`.
///
/// @param state Unused.
/// @param emit The function that adds an observation to the pass.
/// @param emitter The first argument to pass to `emit`.
static void list_check(void* state, rasp_emit emit, void* emitter) {
  (void)state;
  static const rasp_string items[] = {{.data = "a", .size = 1}, {.data = "bc", .size = 2}};
  const rasp_observation observation = {
      .signal = {.data = "c.list", .size = 6},
      .source = {.data = "c", .size = 1},
      .status = RASP_STATUS_OK,
      .value = {.kind = RASP_VALUE_STRING_LIST, .list = {.items = items, .count = 2}},
  };
  emit(emitter, &observation);
}

/// Remembers how many observations the pass had.
///
/// @param state Where to write the count.
/// @param observations Unused.
/// @param count The number of observations.
static void remember(void* state, const rasp_observation* observations, size_t count) {
  (void)observations;
  *(size_t*)state = count;
}

/// The plugin's checks.
static const rasp_check checks[] = {{.name = {.data = "list", .size = 4}, .run = list_check}};

/// The plugin's table.
static const rasp_plugin plugin = {
    .size = sizeof(rasp_plugin),
    .api_version = RASP_PLUGIN_API_VERSION,
    .name = {.data = "c", .size = 1},
    .version = {.data = "1", .size = 1},
    .state = &seen,
    .checks = checks,
    .check_count = 1,
    .on_pass = remember,
};

/// The table, as rasp_plugin_init would return it.
///
/// @return The table.
const rasp_plugin* rasp_test_c_plugin(void) { return &plugin; }

/// How many observations the last pass had, as the plugin's on_pass saw it.
///
/// @return The count, 0 before the first pass.
size_t rasp_test_c_plugin_seen(void) { return seen; }
