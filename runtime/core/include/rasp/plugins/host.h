/// Host, which runs the plugins compiled into the runtime with the built-in checks.

#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins {

/// The signal of the observation that says whether a plugin accepted its config.
inline constexpr std::string_view kLoadSignal = "plugin.load";

/// The largest plugin config the runtime reads, in bytes.
inline constexpr std::size_t kMaxConfigSize = std::size_t{64} * 1024;

/// Reads the config of one plugin.
///
/// @param name The plugin's name.
/// @return The plugin's config. Empty when the plugin has none, or when it can't be read or is larger than
/// kMaxConfigSize.
using ConfigReader = std::string (*)(std::string_view name);

/// The plugins compiled into the runtime, once initialised: runs their checks after the built-in checks, and gives them
/// all the observations.
class Host {
 public:
  /// Initialises every plugin of `plugins`, in order.
  ///
  /// Each plugin's `init` is called once, here, with what `read_config` returns for the plugin's name. A plugin whose
  /// `init` returns `false` declines: its checks never run, and it receives no observations.
  ///
  /// @param plugins The plugins, in the order their checks run.
  /// @param read_config Reads the config of each plugin.
  Host(std::span<const Plugin* const> plugins, ConfigReader read_config);

  /// Runs the plugins after the built-in checks.
  ///
  /// It adds one `plugin.load` observation per plugin, read through the plugin's name: with status `kOk` and no value
  /// when the plugin accepted its config, and with status `kError` when it declined. Then it runs every check of every
  /// plugin that accepted, in order, and gives each of these plugins that has an `on_observations` all the
  /// observations: the built-in ones, the `plugin.load` ones and those of every plugin's checks.
  ///
  /// @param observations The observations of the built-in checks.
  /// @return The built-in observations, then the `plugin.load` ones, then those of the plugins' checks.
  [[nodiscard]] std::vector<Observation> run(std::vector<Observation> observations) const;

 private:
  /// The `plugin.load` observation of every plugin, in order.
  std::vector<Observation> load_observations_;
  /// The plugins that accepted their config, in order.
  std::vector<const Plugin*> accepted_;
};

}  // namespace rasp::plugins
