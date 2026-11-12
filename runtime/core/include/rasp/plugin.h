/// The API of the plugins compiled into the RASP runtime.

#pragma once

#include <memory>
#include <span>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"

namespace rasp {
struct CycleSnapshot;
}

namespace rasp::plugins {

/// A check.
///
/// @param context The values the plugins share, the same in every call. It lives as long as the process.
/// @return What the check observed.
using Check = std::vector<Observation> (*)(Context& context);

/// A plugin compiled into the runtime.
struct Plugin {
  /// Initialises the plugin. The runtime calls it once, when it starts, before the plugin's checks and its
  /// `on_observations`.
  ///
  /// @param config The runtime's config, valid only during the call.
  /// @param context The values the plugins share, the same in every call. It lives as long as the process.
  void (*init)(const Config& config, Context& context);
  /// The plugin's checks.
  std::span<const Check> checks;
  /// Receives observations retained for this dispatch. May be null.
  /// Monitor dispatch is bounded to 256 observations, 64 KiB text and 64 entries per string list; oversized
  /// observations are dropped whole. This span may therefore omit measured data and carries no drop/coverage
  /// accounting. Prefer on_cycle to consume and retain the owned snapshot with that metadata.
  /// Direct legacy run_plugins calls preserve their unbounded behavior without cycle metadata.
  ///
  /// @param observations The retained monitor observations, or direct legacy results, valid only during the call.
  /// @param context The values the plugins share, the same in every call. It lives as long as the process.
  void (*on_observations)(std::span<const Observation> observations, Context& context) = nullptr;
  /// Receives the immutable completed monitor snapshot after this plugin's legacy callback. May be null.
  /// Its local_decisions interpret only the retained builtin prefix, stay unverified/report-only, and
  /// distinguish unavailable rows from predicates_evaluated. No callback can mutate a retained cycle.
  /// Direct legacy run_plugins calls do not invoke it. Retain the pointer for asynchronous consumption.
  /// @param snapshot Metadata and observations with shared immutable ownership.
  /// @param context Process plugin values; the cycle key contains the same snapshot during callbacks.
  void (*on_cycle)(const std::shared_ptr<const CycleSnapshot>& snapshot, Context& context) = nullptr;
};

}  // namespace rasp::plugins
