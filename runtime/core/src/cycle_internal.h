/// Internal saturating counters for bounded cycle metadata.
#pragma once
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

#include "rasp/cycle.h"
#include "rasp/observation.h"
namespace rasp {
/// Mutable call-lifetime state; only its immutable snapshot escapes dispatch.
struct CycleDispatch {
  /// Bounded metadata assembled for this run.
  CycleMetadata metadata;
  /// Initial clock sample.
  CycleClockReading start;
  /// Platform sampling boundary.
  CycleClockReading (*clock)() = nullptr;
  /// Final owned snapshot, set before synchronous callbacks.
  std::shared_ptr<const CycleSnapshot> snapshot;
};
/// Finalizes clocks, coverage and ownership only after synchronous checks return.
/// @param cycle Call-lifetime mutable metadata and clock samples.
/// @param observations Bounded observations transferred into the immutable snapshot.
void finish_cycle(CycleDispatch& cycle, std::vector<Observation> observations);

/// Adds a count, marking overflow rather than wrapping an untrusted summary.
inline void add_cycle_count(std::uint64_t& count, std::uint64_t amount, CycleMetadata& metadata) {
  if (amount > std::numeric_limits<std::uint64_t>::max() - count) {
    count = std::numeric_limits<std::uint64_t>::max();
    metadata.overflow = true;
  } else {
    count += amount;
  }
}
}  // namespace rasp
