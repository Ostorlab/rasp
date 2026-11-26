/// The Android inline-hook check: whether a system function the runtime calls was patched or redirected.

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "util/raw_file.h"

namespace rasp::android::checks {

/// A function the inline-hook check verifies.
struct HookTarget {
  std::string_view name;
  /// The address the runtime calls the function at.
  std::uintptr_t address = 0;
};

/// Whether a mapped file is a library the verified functions may belong to.
using SystemLibraryPredicate = bool (*)(std::string_view path);

/// Whether `path` is the platform's libc or libdl.
[[nodiscard]] bool is_system_libc(std::string_view path);

/// Runs the inline-hook check and returns what it observed.
///
/// @return hook.inline through memory_file, unsupported off Android.
[[nodiscard]] std::vector<Observation> inline_hooks();

/// Verifies that each of `targets` lies in an executable mapping of a system library and starts with the same bytes in
/// memory as in that library's file.
///
/// @param maps_path The memory map, `/proc/self/maps` on a device.
/// @param is_system_library Whether a mapped file is a library the functions may belong to.
/// @return hook.inline through memory_file: the name of each function whose first bytes differ from its file's, and
/// `<name> -> <where>` for each function outside a system library. It has an error status when the map, or the memory
/// or file of a function, can't be read.
[[nodiscard]] std::vector<Observation> observe_inline_hooks(std::string_view maps_path,
                                                            std::span<const HookTarget> targets,
                                                            SystemLibraryPredicate is_system_library = is_system_libc,
                                                            const rasp::util::ProcessAccess& access = {});

}  // namespace rasp::android::checks
