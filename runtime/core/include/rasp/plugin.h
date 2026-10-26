/// The plugin API: what a plugin exports and what the runtime gives it. It is plain C (C11) and C++, so a plugin can
/// be written in either.
///
/// A plugin is a shared library that exports one function, rasp_plugin_init. On Android it is
/// `librasp_plugin_<name>.so`, next to `librasp.so`. On iOS it is `rasp_plugin_<name>.framework`, whose binary is
/// `rasp_plugin_<name>`, in the app's `Frameworks/`. The packer adds it and lists it in the plugin list. A plugin adds
/// checks and sees each pass's observations; what it does with them is its own business.
///
/// The contract:
///
/// - The runtime loads the listed plugins once, in list order, on its monitoring thread, and calls each one's
///   rasp_plugin_init. A plugin that is missing, can't be loaded, has no rasp_plugin_init, returns NULL or returns a
///   table the runtime refuses is skipped.
/// - Then, every 60 seconds, the runtime runs a pass: its built-in checks, then the checks of every plugin (plugins in
///   list order, checks in the order of `checks`), then the `on_pass` of every plugin, with every observation of the
///   pass, its own included.
/// - Every call to a plugin comes from the runtime's monitoring thread, one at a time, never two at once. The thread's
///   stack is 256 KiB. On Android it is not attached to the Java VM.
/// - Every pointer the runtime passes to a plugin is borrowed: it is valid only until the call returns. A plugin
///   copies what it keeps. `emit` copies the observation before it returns.
/// - The table rasp_plugin_init returns, and everything it points to, must stay valid and unchanged for the life of the
///   process. The runtime never unloads a plugin and has no shutdown call.
/// - A plugin's name matches `[a-z][a-z0-9_]{0,31}` and equals the name it is listed under. Its signals start with
///   `<name>.`. The runtime drops an observation it refuses (a signal without that prefix, a string over its limit, an
///   unknown status or value kind, or too many observations or bytes in one pass) and adds a `plugin.signal`
///   observation with status error and the plugin's name as source in its place.
/// - Every pass holds one `plugin.load` observation per listed plugin, with the plugin's name as source and no value:
///   status ok when the plugin is loaded, error when it was skipped.
/// - A plugin never crashes, never ends the process, never lets an exception or a signal escape, and returns quickly:
///   it runs inside the protected app, and a check that blocks holds up every later one.
///
/// Limits the runtime enforces: at most 16 plugins and 64 checks per plugin; a plugin's config is at most 64 KiB; a
/// version, check name, signal or source is at most 128 bytes; a string value or list item is at most 4096 bytes, and a
/// list at most 256 items; in one pass a plugin emits at most 256 observations and 256 KiB of strings.

#pragma once

// NOLINTBEGIN(modernize-deprecated-headers, modernize-use-using, readability-identifier-naming, cppcoreguidelines-macro-usage, modernize-macro-to-enum, cppcoreguidelines-use-enum-class, cppcoreguidelines-pro-type-union-access): a C header keeps C's headers, typedefs, names, macros, enums and unions.

#ifndef __cplusplus
#include <stdbool.h>
#endif
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// The version of this API. A plugin sets its table's `api_version` to it.
#define RASP_PLUGIN_API_VERSION 1

/// Text or bytes: `size` bytes at `data`, not necessarily followed by a NUL byte.
typedef struct rasp_string {
  /// The first byte. It may be NULL only when `size` is 0.
  const char* data;
  /// The number of bytes.
  size_t size;
} rasp_string;

/// Whether a check produced a value, and if not, why. The same values, in the same order, as the runtime's own status.
typedef enum rasp_status {
  /// The check ran and produced a value.
  RASP_STATUS_OK,
  /// The check cannot run here, for example on a simulator.
  RASP_STATUS_UNSUPPORTED,
  /// The check ran but failed, for example because a system call returned an error.
  RASP_STATUS_ERROR,
  /// The check did not finish in time.
  RASP_STATUS_TIMEOUT,
} rasp_status;

/// Which member of a rasp_value holds the value.
typedef enum rasp_value_kind {
  /// No value, as when the check produced none.
  RASP_VALUE_NONE,
  /// `boolean` holds the value.
  RASP_VALUE_BOOL,
  /// `integer` holds the value.
  RASP_VALUE_INT,
  /// `string` holds the value.
  RASP_VALUE_STRING,
  /// `list` holds the value.
  RASP_VALUE_STRING_LIST,
} rasp_value_kind;

/// A list of strings: `count` strings at `items`.
typedef struct rasp_string_list {
  /// The first string. It may be NULL only when `count` is 0.
  const rasp_string* items;
  /// The number of strings.
  size_t count;
} rasp_string_list;

/// The value of an observation: nothing, a boolean, an integer, a string or a list of strings, as `kind` says.
typedef struct rasp_value {
  /// Which member holds the value. Only that member is read.
  rasp_value_kind kind;
  /// The value, in the member `kind` names.
  union {
    /// The value when `kind` is RASP_VALUE_BOOL.
    bool boolean;
    /// The value when `kind` is RASP_VALUE_INT.
    int64_t integer;
    /// The value when `kind` is RASP_VALUE_STRING.
    rasp_string string;
    /// The value when `kind` is RASP_VALUE_STRING_LIST.
    rasp_string_list list;
  };
} rasp_value;

/// One raw fact observed by one check, read through one source.
typedef struct rasp_observation {
  /// What was observed, such as `example.ping`. A plugin's signals start with its name and a dot.
  rasp_string signal;
  /// How it was read, such as `stat`.
  rasp_string source;
  /// Whether the check produced a value, and if not, why.
  rasp_status status;
  /// What the check found, or RASP_VALUE_NONE when it produced no value.
  rasp_value value;
} rasp_observation;

/// What the runtime tells a plugin when it initialises it.
typedef struct rasp_host {
  /// The size of this struct as the runtime knows it. A plugin reads only the fields that fit in it.
  uint32_t size;
  /// The newest API version the runtime supports, RASP_PLUGIN_API_VERSION when it was built.
  uint32_t api_version;
  /// The runtime's version, such as `0.2.0`.
  rasp_string runtime_version;
  /// The platform: `android` or `ios`.
  rasp_string platform;
  /// The plugin's config, the opaque bytes the packer was given for it, at most 64 KiB. Empty when there is none.
  rasp_string config;
  /// The process's `JavaVM*` on Android, NULL on iOS.
  void* java_vm;
} rasp_host;

/// Adds an observation to the pass. A check calls it as many times as it has observations, only while it runs, with
/// the `emitter` it was given. The observation is copied before it returns.
///
/// @param emitter The `emitter` the check was given.
/// @param observation The observation to add.
typedef void (*rasp_emit)(void* emitter, const rasp_observation* observation);

/// One check of a plugin.
typedef struct rasp_check {
  /// The check's name, for the plugin's own use.
  rasp_string name;
  /// Runs the check once, and reports what it observed through `emit`.
  ///
  /// @param state The plugin's `state`.
  /// @param emit The function that adds an observation to the pass.
  /// @param emitter The first argument to pass to `emit`.
  void (*run)(void* state, rasp_emit emit, void* emitter);
} rasp_check;

/// What a plugin gives the runtime: who it is, its checks, and what it does with each pass.
typedef struct rasp_plugin {
  /// The size of this struct as the plugin knows it, `sizeof(rasp_plugin)`. The runtime reads only the fields that fit.
  uint32_t size;
  /// The API version the plugin was built for, RASP_PLUGIN_API_VERSION.
  uint32_t api_version;
  /// The plugin's name: the name it is listed under, matching `[a-z][a-z0-9_]{0,31}`.
  rasp_string name;
  /// The plugin's version, such as `1.0.0`.
  rasp_string version;
  /// What the runtime passes back to every `run` and `on_pass`. The runtime never reads it.
  void* state;
  /// The plugin's checks, in the order they run. It may be NULL only when `check_count` is 0.
  const rasp_check* checks;
  /// The number of checks.
  size_t check_count;
  /// Receives every observation of a pass, once the pass's checks are done. It may be NULL.
  ///
  /// @param state The plugin's `state`.
  /// @param observations The observations of the pass: the runtime's, then `plugin.load` and the plugins' own.
  /// @param count The number of observations.
  void (*on_pass)(void* state, const rasp_observation* observations, size_t count);
} rasp_plugin;

/// Initialises the plugin. It is the one symbol a plugin exports. The runtime calls it once, after it loads the plugin.
///
/// @param host What the runtime tells the plugin: its version, the platform and the plugin's config.
/// @return The plugin's table, which must stay valid for the life of the process, or NULL to decline to run.
__attribute__((visibility("default"))) const rasp_plugin* rasp_plugin_init(const rasp_host* host);

#ifdef __cplusplus
}
#endif

// NOLINTEND(modernize-deprecated-headers, modernize-use-using, readability-identifier-naming, cppcoreguidelines-macro-usage, modernize-macro-to-enum, cppcoreguidelines-use-enum-class, cppcoreguidelines-pro-type-union-access)
