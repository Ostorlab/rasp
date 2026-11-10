/// Reading an uncompressed entry straight from an APK, without inflating anything.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::android::apk {

/// Reads one stored (uncompressed) entry from an APK by name.
///
/// The packer writes the runtime's assets stored, not compressed, so the runtime reads them without an inflate step
/// and without a zip library. The APK is memory-mapped and parsed through its central directory; an entry that is
/// compressed, rather than stored, is refused.
///
/// @param apk_path The APK file to read.
/// @param name The entry's full name in the APK, such as `assets/rasp/payload.bin`.
/// @return The entry's bytes. Nothing when the file can't be mapped, the entry is absent, the entry is compressed, or
/// the archive is malformed.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_stored_entry(const std::string& apk_path,
                                                                         std::string_view name);

/// Reads the stub dex: the highest-numbered `classesN.dex` entry of the APK, which the packer always adds last, after
/// the app's clear framework dexes. The key schedule folds the stub's digest into the root key, so a repackaged APK
/// whose stub was edited to load extra code derives a different key and nothing decrypts.
///
/// @param apk_path The APK file to read.
/// @return The stub dex's bytes. Nothing when the file can't be mapped, the APK holds no `classesN.dex` entry, or
/// the entry is compressed.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_stub_entry(const std::string& apk_path);

/// Reads a digest over every stored entry of the APK, excluding the entries the signing step adds (`META-INF/`),
/// the fold's own outputs (`assets/rasp/`, `assets/business/`), and the runtime library itself (`lib/<abi>/librasp.so`,
/// whose bytes chain A already covers). The key schedule folds this digest into the root key, so a repackaged APK
/// that edits any dex, the manifest, a resource, or adds any library derives a different key and nothing decrypts.
///
/// @param apk_path The APK file to read.
/// @return The 32-byte digest. Nothing when the file can't be mapped or the archive is malformed.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_apk_digest(const std::string& apk_path);

}  // namespace rasp::android::apk
