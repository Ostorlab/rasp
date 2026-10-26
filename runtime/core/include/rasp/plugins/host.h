/// The runtime's side of the plugin API (rasp/plugin.h): reading the plugin list, checking the tables plugins return,
/// running their checks in a pass, and giving every plugin the observations of the pass.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins {

/// The most plugins a plugin list names. Later lines are ignored.
inline constexpr std::size_t kMaxPlugins = 16;
/// The largest plugin list, in bytes.
inline constexpr std::size_t kMaxListSize = 1024;
/// The largest config of one plugin, in bytes.
inline constexpr std::size_t kMaxConfigSize = std::size_t{64} * 1024;
/// The longest plugin name, in bytes.
inline constexpr std::size_t kMaxNameSize = 32;
/// The longest version, check name, signal or source a plugin hands over, in bytes.
inline constexpr std::size_t kMaxTextSize = 128;
/// The longest string value or list item a plugin hands over, in bytes.
inline constexpr std::size_t kMaxValueSize = 4096;
/// The most items in a list value a plugin hands over.
inline constexpr std::size_t kMaxListItems = 256;
/// The most checks one plugin declares.
inline constexpr std::size_t kMaxChecks = 64;
/// The most observations one plugin emits in one pass.
inline constexpr std::size_t kMaxObservations = 256;
/// The most bytes of strings one plugin emits in one pass.
inline constexpr std::size_t kMaxPassBytes = std::size_t{256} * 1024;

/// The signal of the observation that says whether a listed plugin was loaded.
inline constexpr std::string_view kLoadSignal = "plugin.load";
/// The signal of the observation that replaces an observation the runtime refused from a plugin.
inline constexpr std::string_view kRefusedSignal = "plugin.signal";

/// Whether `name` is a valid plugin name: a lowercase ASCII letter, then at most 31 lowercase ASCII letters, digits or
/// underscores.
///
/// @param name The name to check.
/// @return `true` when it matches `[a-z][a-z0-9_]{0,31}`.
[[nodiscard]] bool valid_name(std::string_view name);

/// The names in the plugin list `text`, in load order.
///
/// The list holds one name per line. A line ends with a line feed, and a carriage return before it is dropped. Empty
/// lines are skipped.
/// A line that isn't a valid name is still returned, so the caller reports that plugin as not loaded. At most
/// kMaxPlugins names are returned; the lines after them are ignored.
///
/// @param text The content of the plugin list.
/// @return The names, in the order of the list.
[[nodiscard]] std::vector<std::string> parse_list(std::string_view text);

/// What the runtime tells a plugin's rasp_plugin_init.
///
/// @param platform The platform name, `android` or `ios`. It must outlive the returned value.
/// @param config The plugin's config, opaque bytes. It must outlive the returned value.
/// @param java_vm The process's `JavaVM*` on Android, null on iOS.
/// @return The host description, of this runtime's size and API version.
[[nodiscard]] rasp_host host_info(std::string_view platform, std::string_view config, void* java_vm);

/// Copies an observation a plugin handed over into a runtime observation, checking every field.
///
/// @param observation The plugin's observation.
/// @return The copy. Nothing when a string is null with a size above 0 or is over its limit, the status or the value
/// kind is unknown, or a list is null with items or has more than kMaxListItems items.
[[nodiscard]] std::optional<Observation> copy_observation(const rasp_observation& observation);

/// A C view of runtime observations, as `on_pass` receives them.
///
/// Each record points into the observation it was built from, so the view is valid only while those observations
/// exist and don't change.
class ObservationView {
 public:
  /// Builds the view of `observations`.
  ///
  /// @param observations The observations to view. They must outlive the view and not change while it exists.
  explicit ObservationView(std::span<const Observation> observations);

  /// The records, one per observation, in the same order.
  ///
  /// @return The records, valid while the view and the observations exist.
  [[nodiscard]] std::span<const rasp_observation> records() const;

 private:
  /// The items of every list value, one after another; each list record points to its own run of them.
  std::vector<rasp_string> items_;
  /// One record per observation.
  std::vector<rasp_observation> records_;
};

/// One plugin of the plugin list: the name it is listed under, and the table its rasp_plugin_init returned.
struct Listed {
  /// The name in the plugin list.
  std::string name;
  /// The table rasp_plugin_init returned. Null when the plugin wasn't loaded, had no rasp_plugin_init, or declined.
  const rasp_plugin* table = nullptr;
};

/// The plugins of a protected app, once loaded: runs their checks in each pass and gives them the pass.
///
/// The host lives as long as the thread that runs the passes, and only that thread uses it. It can't be copied or
/// moved, because each plugin's checks receive the address of the host's own record of where to emit.
class Host {
 public:
  /// Checks the table of every listed plugin and keeps those it accepts.
  ///
  /// A table is accepted when it is not null, its `size` covers every version 1 field, its `api_version` is from 1 to
  /// RASP_PLUGIN_API_VERSION, its name is valid and equals the listed name, its strings are valid and within their
  /// limits, and it declares at most kMaxChecks checks, each with a `run` function. Only the version 1 fields are read,
  /// once, here.
  ///
  /// @param listed The plugins of the plugin list, in load order.
  explicit Host(std::span<const Listed> listed);
  /// Deleted: the plugins' checks hold the address of the host's records.
  Host(const Host&) = delete;
  /// Deleted: the plugins' checks hold the address of the host's records.
  Host& operator=(const Host&) = delete;
  /// Deleted: the plugins' checks hold the address of the host's records.
  Host(Host&&) = delete;
  /// Deleted: the plugins' checks hold the address of the host's records.
  Host& operator=(Host&&) = delete;
  /// Releases the host's records. The plugins stay loaded.
  ~Host() = default;

  /// Completes a pass whose built-in checks reported `observations`.
  ///
  /// It adds one `plugin.load` observation per listed plugin, runs every check of every accepted plugin in order, then
  /// calls every accepted plugin's `on_pass` with all the observations of the pass.
  ///
  /// @param observations The observations of the runtime's built-in checks.
  /// @return Every observation of the pass: the built-in ones, then `plugin.load` ones, then the plugins' own.
  [[nodiscard]] std::vector<Observation> run_pass(std::vector<Observation> observations);

 private:
  /// The function of a plugin's check.
  using CheckFunction = void (*)(void* state, rasp_emit emit, void* emitter);
  /// The `on_pass` function of a plugin.
  using PassFunction = void (*)(void* state, const rasp_observation* observations, std::size_t count);

  /// Where a plugin's checks emit during a pass, and what they emitted so far. Its address is the `emitter` the checks
  /// receive.
  struct Sink {
    /// The prefix every signal of the plugin starts with: its name and a dot.
    std::string prefix;
    /// The plugin's name, the source of the observations that replace refused ones.
    std::string name;
    /// The observations of the pass while a check of the plugin runs, null otherwise, so a late call adds nothing.
    std::vector<Observation>* observations = nullptr;
    /// How many observations the plugin emitted in this pass.
    std::size_t count = 0;
    /// How many bytes of strings the plugin emitted in this pass.
    std::size_t bytes = 0;
  };

  /// One accepted plugin: what the host keeps of its table, and its sink.
  struct Plugin {
    /// The plugin's `state`.
    void* state = nullptr;
    /// The `run` function of each check, in order.
    std::vector<CheckFunction> checks;
    /// The plugin's `on_pass`, or null.
    PassFunction on_pass = nullptr;
    /// Where its checks emit.
    Sink sink;
  };

  /// Copies what the host keeps of the table of `listed`, when it accepts the table.
  ///
  /// @param listed A plugin of the plugin list.
  /// @return The plugin, or nothing when the table is refused.
  [[nodiscard]] static std::optional<Plugin> accept(const Listed& listed);

  /// Adds the observation `observation` to the pass of the plugin whose sink is `emitter`. It is the `emit` every check
  /// receives.
  ///
  /// @param emitter The plugin's sink.
  /// @param observation The observation to copy.
  static void emit(void* emitter, const rasp_observation* observation);

  /// The `plugin.load` observation of every listed plugin, in list order.
  std::vector<Observation> load_observations_;
  /// The accepted plugins, in list order.
  std::vector<Plugin> plugins_;
};

}  // namespace rasp::plugins
