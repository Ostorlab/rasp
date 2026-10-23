/// The dex that defines the on-demand class loader, which the runtime loads itself instead of the app shipping it.

#pragma once

#include <cstdint>
#include <vector>

namespace rasp::android::loader {

/// The binary name of the class the loader dex defines.
inline constexpr const char* kLoaderClassName = "co.ostorlab.rasp.GeneratingClassLoader";

/// The dex that defines the on-demand class loader.
///
/// The class is `GeneratingClassLoader.java`, next to this file. `cmake/loader_dex.cmake` compiles it with javac and d8
/// when CMake configures the build, and the dex is embedded in the library. The class extends `java.lang.ClassLoader`,
/// has a `(ClassLoader parent, ClassLoader base)` constructor, and a `protected native Class<?> findClass(String)` that
/// the runtime binds at load time.
///
/// @return The bytes of the dex, as a copy the caller owns.
[[nodiscard]] std::vector<std::uint8_t> loader_dex();

}  // namespace rasp::android::loader
