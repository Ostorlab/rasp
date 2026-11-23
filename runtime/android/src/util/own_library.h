/// find_own_library: where the runtime's own library is loaded.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace rasp::android::util {

/// Where the runtime's library is loaded.
struct LoadedLibrary {
  /// The path of the installed library file.
  std::string path;
  /// The load address of the library: its load bias, where the span of its image begins.
  std::uintptr_t load_bias = 0;
  /// The highest virtual address any of its loadable segments reaches, relative to the load address.
  std::uint64_t image_size = 0;
};

/// Finds where the runtime's own library is loaded.
///
/// @return The library, or nothing off Android or when the dynamic linker can't say.
[[nodiscard]] std::optional<LoadedLibrary> find_own_library();

}  // namespace rasp::android::util
