/// Shared production check/dispatch path with immutable bounded monitor handoff.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "cycle_internal.h"
#include "dispatch.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"
namespace rasp::plugins {
namespace {
/// Adds bounded text length without integer overflow.
[[nodiscard]] bool add_text(std::size_t& bytes, std::size_t size, std::size_t limit) {
  if (size > limit || size > 65536 - bytes) {
    return false;
  }
  bytes += size;
  return true;
}
/// Validates the total retained text budget, without changing observations.
[[nodiscard]] bool fits(const Observation& observation, std::size_t& bytes) {
  if (!add_text(bytes, observation.signal.size(), 96) || !add_text(bytes, observation.source.size(), 96)) {
    return false;
  }
  if (const auto* text = std::get_if<std::string>(&observation.value); text != nullptr) {
    return add_text(bytes, text->size(), 1024);
  }
  if (const auto* list = std::get_if<std::vector<std::string>>(&observation.value); list != nullptr) {
    if (list->size() > 64) {
      return false;
    }
    for (const std::string& entry : *list) {
      if (!add_text(bytes, entry.size(), 1024)) {
        return false;
      }
    }
  }
  return true;
}
/// Appends bounded monitor observations and records whole-observation drops.
void append(std::vector<Observation>& output, std::vector<Observation> incoming, CycleMetadata& metadata,
            std::size_t& text_bytes) {
  for (Observation& observation : incoming) {
    std::size_t next_bytes = text_bytes;
    if (output.size() >= 256 || !fits(observation, next_bytes)) {
      add_cycle_count(metadata.dropped, 1, metadata);
      continue;
    }
    text_bytes = next_bytes;
    const auto status = static_cast<std::size_t>(observation.status);
    if (status < metadata.status_counts.size()) {
      add_cycle_count(std::span(metadata.status_counts)[status], 1, metadata);
    } else {
      add_cycle_count(metadata.unknown_status, 1, metadata);
    }
    output.push_back(std::move(observation));
  }
}
}  // namespace
std::vector<Observation> dispatch_plugins(std::span<const Plugin* const> plugins, std::vector<Observation> observations,
                                          Context& context, CycleDispatch* cycle) {
  CycleMetadata* const metadata = cycle == nullptr ? nullptr : &cycle->metadata;
  static_cast<void>(context.take(kCycleSnapshot));
  std::size_t text_bytes = 0;
  if (metadata != nullptr) {
    std::vector<Observation> retained;
    append(retained, std::move(observations), *metadata, text_bytes);
    observations = std::move(retained);
  }
  for (const Plugin* const plugin : plugins) {
    for (const Check check : plugin->checks) {
      std::vector<Observation> incoming = check(context);
      if (metadata == nullptr) {
        std::ranges::move(incoming, std::back_inserter(observations));
      } else {
        add_cycle_count(metadata->plugin_observations, static_cast<std::uint64_t>(incoming.size()), *metadata);
        append(observations, std::move(incoming), *metadata, text_bytes);
      }
    }
  }
  std::shared_ptr<const CycleSnapshot> snapshot;
  std::span<const Observation> callback_observations(observations);
  if (cycle != nullptr) {
    finish_cycle(*cycle, std::move(observations));
    observations.clear();
    snapshot = cycle->snapshot;
    callback_observations = snapshot->observations;
    context.put(kCycleSnapshot, snapshot);
  }
  for (const Plugin* const plugin : plugins) {
    if (plugin->on_observations != nullptr) {
      plugin->on_observations(callback_observations, context);
    }
    if (snapshot != nullptr && plugin->on_cycle != nullptr) {
      plugin->on_cycle(snapshot, context);
    }
  }
  static_cast<void>(context.take(kCycleSnapshot));
  return observations;
}
std::vector<Observation> run_plugins(std::span<const Plugin* const> plugins, std::vector<Observation> observations,
                                     Context& context) {
  const auto guard = context.lock_dispatch();
  return dispatch_plugins(plugins, std::move(observations), context);
}
}  // namespace rasp::plugins
