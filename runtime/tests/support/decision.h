/// Sends real collector fixture outputs through the owning production cycle dispatcher.
#pragma once

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"

namespace rasp::test_support {
/// Publishes measured fixture evidence with the exact production platform catalogue.
/// @param platform Exact native catalogue platform.
/// @param observations Actual outputs from the collector under test, owned by the call.
/// @return Immutable owned run, including local decisions and explicit missing other outputs.
[[nodiscard]] inline std::shared_ptr<const rasp::CycleSnapshot> decide(
    std::string_view platform, const std::vector<rasp::Observation>& observations) {
  const auto catalogue = rasp::cycle_catalogue(platform);
  std::vector<std::string> groups;
  for (const auto& output : catalogue.outputs) {
    if (std::ranges::find(groups, output.group) == groups.end()) {
      groups.emplace_back(output.group);
    }
  }
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  return monitor.run(
      {.build_id = "fixture", .checks = std::move(groups)}, catalogue, {}, context,
      [](const rasp::Config&, const void* argument) {
        return *static_cast<const std::vector<rasp::Observation>*>(argument);
      },
      &observations);
}
}  // namespace rasp::test_support
