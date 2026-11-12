/// Actual finite builtin/plugin measurement path and exact compiled coverage accounting.
#include "rasp/cycle.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cycle_catalogue.h"
#include "cycle_internal.h"
#include "plugins/dispatch.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/util/uuid.h"

namespace rasp {
namespace {
/// Maximum builtin output identities represented in a snapshot.
constexpr std::size_t kMaxOutputs = 256;
/// Maximum known/configured groups.
constexpr std::size_t kMaxGroups = 64;
/// Maximum catalogue name length.
constexpr std::size_t kMaxName = 96;

/// Checks that an externally supplied catalogue name fits the native contract.
[[nodiscard]] bool valid_name(std::string_view name) { return !name.empty() && name.size() <= kMaxName; }

/// Builds bounded owned group state from exact compiled definitions.
void catalogue_state(const CycleCatalogue& catalogue, CycleMetadata& metadata) {
  metadata.catalogue_truncated = catalogue.outputs.size() > kMaxOutputs;
  if (!valid_name(catalogue.platform) || !valid_name(catalogue.catalogue_id) || catalogue.outputs.empty() ||
      metadata.catalogue_truncated) {
    return;
  }
  metadata.platform = catalogue.platform;
  metadata.catalogue_id = catalogue.catalogue_id;
  for (std::size_t index = 0; index < catalogue.outputs.size(); ++index) {
    const CycleOutput& output = catalogue.outputs[index];
    if (!valid_name(output.group) || !valid_name(output.signal) || !valid_name(output.source)) {
      metadata.catalogue_truncated = true;
      return;
    }
    for (std::size_t previous = 0; previous < index; ++previous) {
      if (catalogue.outputs[previous].signal == output.signal && catalogue.outputs[previous].source == output.source) {
        return;
      }
    }
    if (std::ranges::find(metadata.groups, output.group, &CycleGroup::name) == metadata.groups.end()) {
      if (metadata.groups.size() == kMaxGroups) {
        metadata.catalogue_truncated = true;
        return;
      }
      metadata.groups.push_back({.name = std::string(output.group), .enabled = std::nullopt});
    }
  }
  metadata.catalogue_known = true;
}

/// Keeps missing config distinct from disabled groups and foreign configured names.
void config_state(const Config& config, CycleMetadata& metadata) {
  if (!config.checks.has_value()) {
    return;
  }
  metadata.config_truncated = config.checks->size() > kMaxGroups;
  if (metadata.config_truncated) {
    return;
  }
  for (const std::string& group : *config.checks) {
    if (!valid_name(group)) {
      metadata.config_truncated = true;
    }
  }
  metadata.config_known = !metadata.config_truncated;
  if (!metadata.config_known || !metadata.catalogue_known) {
    return;
  }
  for (CycleGroup& group : metadata.groups) {
    group.enabled = is_check_enabled(config, group.name);
  }
  for (const std::string& name : *config.checks) {
    if (std::ranges::find(metadata.groups, name, &CycleGroup::name) == metadata.groups.end()) {
      add_cycle_count(metadata.unknown_groups, 1, metadata);
    }
  }
}

/// Measures exact builtin coverage before plugins or retention caps can alter it.
void builtin_coverage(const Config& config, const CycleCatalogue& catalogue, std::span<const Observation> observations,
                      CycleMetadata& metadata) {
  if (!metadata.config_known || !metadata.catalogue_known) {
    return;
  }
  metadata.expected = 0;
  std::array<bool, kMaxOutputs> seen{};
  const std::span seen_flags(seen);
  for (const Observation& observation : observations) {
    const auto output = std::ranges::find_if(catalogue.outputs, [&](const CycleOutput& candidate) {
      return candidate.signal == observation.signal && candidate.source == observation.source;
    });
    if (output == catalogue.outputs.end() || !is_check_enabled(config, output->group)) {
      add_cycle_count(metadata.extra, 1, metadata);
      continue;
    }
    const auto index = static_cast<std::size_t>(output - catalogue.outputs.begin());
    if (seen_flags[index]) {
      add_cycle_count(metadata.extra, 1, metadata);
    } else {
      seen_flags[index] = true;
      add_cycle_count(metadata.seen, 1, metadata);
    }
  }
  for (std::size_t index = 0; index < catalogue.outputs.size(); ++index) {
    const CycleOutput& output = catalogue.outputs[index];
    if (is_check_enabled(config, output.group)) {
      add_cycle_count(*metadata.expected, 1, metadata);
      if (!seen_flags[index]) {
        metadata.missing.push_back({.signal = std::string(output.signal), .source = std::string(output.source)});
      }
    }
  }
}

}  // namespace

/// Finalizes metadata only after every synchronous check has actually returned.
void finish_cycle(CycleDispatch& cycle, std::vector<Observation> observations) {
  CycleMetadata& metadata = cycle.metadata;
  const CycleClockReading end = cycle.clock();
  if (cycle.start.monotonic_ns.has_value() && end.monotonic_ns.has_value() && *cycle.start.monotonic_ns >= 0 &&
      *end.monotonic_ns >= *cycle.start.monotonic_ns) {
    metadata.duration_ns =
        static_cast<std::uint64_t>(*end.monotonic_ns) - static_cast<std::uint64_t>(*cycle.start.monotonic_ns);
  }
  constexpr std::int64_t kMinWallMs = 946684800000LL;
  constexpr std::int64_t kMaxWallMs = 4102444800000LL;
  if (end.unix_ms.has_value() && *end.unix_ms >= kMinWallMs && *end.unix_ms < kMaxWallMs) {
    metadata.observed_at_unix_ms = end.unix_ms;
  }
  metadata.execution_finished = true;
  metadata.complete = metadata.config_known && metadata.catalogue_known && metadata.sequence.has_value() &&
                      metadata.duration_ns.has_value() && metadata.unknown_groups == 0 && metadata.missing.empty() &&
                      metadata.extra == 0 && metadata.dropped == 0 && metadata.unknown_status == 0 &&
                      !metadata.overflow;
  LocalDecisionReport decisions = evaluate_local_decisions(
      metadata, std::span<const Observation>(observations).first(cycle.builtin_observations), cycle.catalogue);
  cycle.snapshot = std::make_shared<const CycleSnapshot>(CycleSnapshot{.metadata = std::move(metadata),
                                                                       .observations = std::move(observations),
                                                                       .local_decisions = std::move(decisions)});
}

CycleCatalogue cycle_catalogue(std::string_view platform) {
  if (platform == "android") {
    return {.platform = "android", .catalogue_id = kCycleCatalogueId, .outputs = kAndroidCycleOutputs};
  }
  if (platform == "ios") {
    return {.platform = "ios", .catalogue_id = kCycleCatalogueId, .outputs = kIosCycleOutputs};
  }
  return {};
}

CycleMonitor::CycleMonitor(CycleClockReading (*clock)(), std::uint64_t last_sequence)
    : session_id_(util::new_uuid()), sequence_(last_sequence), clock_(clock) {}

std::shared_ptr<const CycleSnapshot> CycleMonitor::run(const Config& config, const CycleCatalogue& catalogue,
                                                       std::span<const plugins::Plugin* const> plugins,
                                                       plugins::Context& context,
                                                       std::vector<Observation> (*builtins)(const Config&, const void*),
                                                       const void* argument) {
  const std::scoped_lock monitor_guard(mutex_);
  const auto dispatch_guard = context.lock_dispatch();
  static_cast<void>(context.take(plugins::kCycleSnapshot));
  CycleDispatch cycle;
  cycle.catalogue = catalogue;
  cycle.clock = clock_;
  CycleMetadata& metadata = cycle.metadata;
  metadata.session_id = session_id_;
  metadata.run_id = util::new_uuid();
  if (sequence_ == std::numeric_limits<std::uint64_t>::max()) {
    metadata.overflow = true;
  } else {
    metadata.sequence = ++sequence_;
  }
  catalogue_state(catalogue, metadata);
  config_state(config, metadata);
  cycle.start = clock_();
  std::vector<Observation> observations = builtins(config, argument);
  builtin_coverage(config, catalogue, observations, metadata);
  static_cast<void>(plugins::dispatch_plugins(plugins, std::move(observations), context, &cycle));
  return cycle.snapshot;
}
}  // namespace rasp
