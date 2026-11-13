/// Bounded dyld executable-image observation with owned native access boundaries.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "rasp/posix/provenance.h"

namespace rasp::ios::checks {
/// Copied image identity and header/commands; no pointer survives collection.
struct ProvenanceImage {
  std::string name;
  std::uintptr_t header_address = 0;
  std::int64_t slide = 0;
  std::vector<std::uint8_t> bytes;
  friend bool operator==(const ProvenanceImage&, const ProvenanceImage&) = default;
};
/// Replace only dyld/own-task I/O, retaining real parsing, bracketing and reductions.
struct DyldCalls {
  void* context = nullptr;
  provenance::Result<std::uint32_t> (*count)(void*, provenance::Budget&) = nullptr;
  provenance::Result<ProvenanceImage> (*image)(void*, std::uint32_t, provenance::Budget&) = nullptr;
};
/// Public dyld and exact-length own-task copy adapters; unavailable off Apple platforms.
[[nodiscard]] DyldCalls native_dyld_calls();
/// Collects two bounded copied passes and reduces only declared executable segments.
/// @param locations Public main-bundle root or explicit unavailable metadata.
/// @param calls Native accessors, or fixture replacements at that boundary only.
/// @param clock Cooperative monotonic clock, never a hard native-call deadline.
/// @return Fixed data/meta pair; errors carry no partial inventory.
[[nodiscard]] provenance::Pair collect_module_provenance(const provenance::Locations& locations,
                                                         DyldCalls calls = native_dyld_calls(),
                                                         provenance::Clock clock = provenance::monotonic_ns);
/// Physical-iOS gate used by the explicitly selected hooks dispatcher.
[[nodiscard]] provenance::Pair module_provenance();
}  // namespace rasp::ios::checks
