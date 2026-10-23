/// The dex that defines the on-demand class loader, from the bytes that `cmake/loader_dex.cmake` embeds when CMake
/// configures the build.

#include "loader/loader_dex.h"

#include <cstdint>
#include <vector>

#include "loader/loader_dex_bytes.h"

namespace rasp::android::loader {

std::vector<std::uint8_t> loader_dex() { return {kLoaderDexBytes.begin(), kLoaderDexBytes.end()}; }

}  // namespace rasp::android::loader
