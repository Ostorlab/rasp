/// Owned measurement snapshots and the finite path used by both platform monitors.
#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/decision.h"
#include "rasp/observation.h"

namespace rasp::plugins {
struct Plugin;
}
namespace rasp {
class LocalPolicyState;
/// An exact compiled builtin output identity. The generated catalogue owns its strings.
struct CycleOutput {
  /// Config group enabling this output.
  std::string_view group;
  /// Observation signal.
  std::string_view signal;
  /// Observation source.
  std::string_view source;
};
/// A compiled catalogue, never a self-hash of a config-mutated binary.
struct CycleCatalogue {
  /// Platform of these definitions.
  std::string_view platform;
  /// Canonical release catalogue SHA-256.
  std::string_view catalogue_id;
  /// All builtin identities; plugin outputs remain unmodelled.
  std::span<const CycleOutput> outputs;
};
/// Returns the exact generated release catalogue for a named platform.
/// @param platform Android or iOS platform name.
/// @return Static definitions, or unavailable catalogue for an unknown platform.
[[nodiscard]] CycleCatalogue cycle_catalogue(std::string_view platform);
/// Clock samples with explicit availability, injectable at the finite monitor seam.
struct CycleClockReading {
  /// Nonnegative monotonic ticks in nanoseconds; absent on clock failure.
  std::optional<std::int64_t> monotonic_ns = std::nullopt;
  /// Device wall time in Unix milliseconds, validated at completion.
  std::optional<std::int64_t> unix_ms = std::nullopt;
};
/// Reads checked platform monotonic and device wall clocks.
/// @return Unverified clock samples; monotonic negative values are unavailable.
[[nodiscard]] CycleClockReading read_cycle_clock();
/// Owned enabled/disabled/unknown state for one known catalogue group.
struct CycleGroup {
  /// Config group name.
  std::string name;
  /// Null when config is unavailable, false when disabled.
  std::optional<bool> enabled;
};
/// An owned missing builtin identity.
struct CycleMissing {
  /// Signal that did not appear.
  std::string signal;
  /// Source that did not appear.
  std::string source;
};
/// Versioned unverified context for an actual completed synchronous run.
struct CycleMetadata {
  /// Independent native contract version, not a wire message version.
  std::uint32_t version = 1;
  /// Process lifetime UUID, unrelated to install identity.
  std::string session_id;
  /// UUID of this execution, never a delivery batch ID.
  std::string run_id;
  /// Monotonic nonzero run ordinal, absent after exhaustion.
  std::optional<std::uint64_t> sequence;
  /// Measured duration; absent for invalid/backwards clocks, zero for equal ticks.
  std::optional<std::uint64_t> duration_ns;
  /// Completion wall time in the backend-supported calendar range.
  std::optional<std::int64_t> observed_at_unix_ms;
  /// Compiled platform, empty when unavailable.
  std::string platform;
  /// Catalogue SHA-256, never the mutable runtime image digest.
  std::string catalogue_id;
  /// Whether config group selection is available and within bounds.
  bool config_known = false;
  /// Whether bounded exact compiled catalogue definitions are available.
  bool catalogue_known = false;
  /// All synchronous checks returned; no claim about stalled/crashed threads.
  bool execution_finished = false;
  /// Full retained snapshot with exact known selected builtin coverage.
  bool complete = false;
  /// Config selection exceeded the bounded representation.
  bool config_truncated = false;
  /// Catalogue exceeded the bounded representation.
  bool catalogue_truncated = false;
  /// Counter or sequence exhausted; never silently wraps.
  bool overflow = false;
  /// Known groups with distinct disabled and unknown states.
  std::vector<CycleGroup> groups;
  /// Unrecognised configured names, preventing full coverage claims.
  std::uint64_t unknown_groups = 0;
  /// Expected enabled builtin identities; null when coverage is unknown.
  std::optional<std::uint64_t> expected;
  /// Unique expected builtin identities present before retention limits.
  std::uint64_t seen = 0;
  /// Missing enabled builtin identities, bounded by the catalogue size.
  std::vector<CycleMissing> missing;
  /// Duplicate, disabled or foreign builtin outputs before retention limits.
  std::uint64_t extra = 0;
  /// Observations dropped whole due to count/text limits.
  std::uint64_t dropped = 0;
  /// Returned plugin observations, without expected plugin counts.
  std::uint64_t plugin_observations = 0;
  /// Retained status counts indexed by Status, including unsupported/error/timeout.
  std::array<std::uint64_t, 4> status_counts{};
  /// Retained observations with an unrecognised status.
  std::uint64_t unknown_status = 0;
};
/// Immutable handoff unit; metadata and observations must always travel together.
struct CycleSnapshot {
  /// Metadata finalised after measurements and before callbacks.
  CycleMetadata metadata;
  /// Owned bounded observations; no spans into a later run.
  std::vector<Observation> observations;
  /// Report-only typed decisions and evidence indices from this exact owned run.
  LocalDecisionReport local_decisions{};
};
/// A process-local monitor state, created on its monitoring thread at startup.
class CycleMonitor {
 public:
  /// Creates the process UUID; optional clock/ordinal support finite boundary tests.
  /// @param clock The non-null sampling function, normally read_cycle_clock.
  /// @param last_sequence Last assigned ordinal, normally zero.
  explicit CycleMonitor(CycleClockReading (*clock)() = read_cycle_clock, std::uint64_t last_sequence = 0);
  /// Executes the same finite builtin/plugin/callback path used by both monitors.
  /// Recursive dispatch on this monitor or Context is unsupported.
  /// @param config Existing selection, unchanged by telemetry.
  /// @param catalogue Exact compiled catalogue with call-lifetime/static backing.
  /// @param plugins Compiled plugins in existing order.
  /// @param context Process plugin values; dispatches serialize on this Context.
  /// @param builtins The actual platform builtin dispatcher, called exactly once.
  /// @param argument Call-lifetime platform dispatcher state, for example iOS environment.
  /// @return Owned immutable snapshot, also published synchronously to callbacks.
  [[nodiscard]] std::shared_ptr<const CycleSnapshot> run(
      const Config& config, const CycleCatalogue& catalogue, std::span<const plugins::Plugin* const> plugins,
      plugins::Context& context, std::vector<Observation> (*builtins)(const Config&, const void*),
      const void* argument = nullptr, LocalPolicyState* policy_state = nullptr);

 private:
  /// Serializes ordinals and clock samples across calls on this monitor.
  std::mutex mutex_;
  /// Secure random process identity.
  std::string session_id_;
  /// Last ordinal, saturating at uint64 max.
  std::uint64_t sequence_;
  /// Clock boundary, replaced only in tests.
  CycleClockReading (*clock_)();
};
}  // namespace rasp
namespace rasp::plugins {
/// Only present during callbacks; asynchronous consumers must retain this owning pointer now.
inline constexpr Key<std::shared_ptr<const CycleSnapshot>> kCycleSnapshot{"rasp.cycle.snapshot.v1"};
}  // namespace rasp::plugins
