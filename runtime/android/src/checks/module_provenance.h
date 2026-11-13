/// Own-process executable maps/native-loader collector for opt-in hooks diagnostics.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "rasp/posix/provenance.h"

namespace rasp::android::checks {
/// A copied loader-declared executable range; never sent as an address.
struct ExecutableInterval {
  std::uintptr_t start = 0;
  std::uintptr_t end = 0;
  std::uint32_t flags = 0;
};
/// Owned native image metadata, reduced before observations leave this collector.
struct ExecutableImage {
  std::string name;
  std::vector<ExecutableInterval> intervals;
};
/// A read result captures errno at the I/O boundary, including EINTR.
struct MapRead {
  std::int64_t size = -1;
  int error = 0;
};
/// Replaceable file boundaries; the collector owns complete reads, limits and cleanup.
struct MapIo {
  void* context = nullptr;
  int (*open)(void*) = nullptr;
  MapRead (*read)(void*, int, std::span<char>) = nullptr;
  int (*close)(void*, int) = nullptr;
};
/// Native enumeration is replaceable without replacing map parsing or reductions.
struct ModuleCalls {
  MapIo maps;
  void* context = nullptr;
  provenance::Result<std::vector<ExecutableImage>> (*images)(void*, provenance::Budget&) = nullptr;
};
/// Creates actual own-proc/native-loader adapters, also exercisable on Linux hosts.
[[nodiscard]] ModuleCalls native_module_calls();
/// Collects maps/native pairs independently, with bounded bracketing and no raw output.
/// @param locations Public app roots; invalid roots become unavailable.
/// @param calls Actual native boundaries or controlled fixture boundaries.
/// @param clock Monotonic cooperative work clock.
/// @return Maps data/meta followed by native image data/meta.
[[nodiscard]] std::vector<Observation> collect_module_provenance(const provenance::Locations& locations,
                                                                 ModuleCalls calls = native_module_calls(),
                                                                 provenance::Clock clock = provenance::monotonic_ns);
/// Standard Android gate for future explicit dispatcher integration; currently never registered.
[[nodiscard]] std::vector<Observation> module_provenance();
}  // namespace rasp::android::checks
