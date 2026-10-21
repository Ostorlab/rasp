/// read_library_file, which reads the bytes of a native library given the path the dynamic loader reports for it,
/// whether that is a plain file or an entry inside an APK (`<apk>!/<entry>`).

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace rasp::android::util {

/// Reads the bytes of the native library at `loader_path`, the path the dynamic loader reports for a loaded object.
///
/// Since Android 6 an app may keep its native libraries uncompressed inside the APK (`extractNativeLibs=false`, the
/// default from API 30). The loader then reports the library's path as `<apk path>!/<zip entry>`, for example
/// `/data/app/~~x==/co.app-1/base.apk!/lib/arm64-v8a/librasp.so`, which is not a file that `fopen` can open. This
/// opens the APK, finds the entry in the zip central directory, and returns the entry's stored bytes. A plain path
/// with no `!/` is read whole as a file. The library is stored uncompressed, so the bytes are the library's ELF image;
/// a compressed entry gives nothing, since this does not inflate.
///
/// @param loader_path The path the loader reports, a plain path or `<apk path>!/<zip entry>`.
/// @param limit The largest content accepted, in bytes.
/// @return The bytes of the library, or nothing when the path can't be read, the APK or entry can't be parsed, the
/// entry is compressed or missing, or the content is longer than `limit` bytes.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_library_file(std::string_view loader_path,
                                                                         std::size_t limit);

}  // namespace rasp::android::util
