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

/// Reads a digest over the APKs installed beside the base APK: their filenames, sorted, each followed by a null,
/// fed into one SHA-256 — the same digest the packer computes over its prediction of the installed set. A split APK
/// installed beside a genuine base shares the app's process and class loader, so its code runs in-process while
/// every base-derived input still matches; the key schedule folds this digest into the root key, so any APK beside
/// the base derives a different key and nothing decrypts.
///
/// @param apk_path The base APK's path, as the runtime resolved it; its directory is the one the store installs
/// splits into.
/// @return The 32-byte digest. Nothing when the install directory can't be read, which fails the recovery the way
/// every unread input does.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_split_digest(const std::string& apk_path);

/// Reads the APKs installed beside the base APK, the base excluded, or nothing when the install directory can't
/// be read.
///
/// @param apk_path The base APK's path, as the runtime resolved it.
/// @return The sibling APKs' filenames, sorted. Nothing when the directory can't be read.
[[nodiscard]] std::optional<std::vector<std::string>> list_split_apks(const std::string& apk_path);

/// Reads a digest over the base APK's class dexes — every `classes.dex` / `classesN.dex` entry's name and
/// uncompressed content, sorted by name, fed into one SHA-256 — the same digest the packer computes over the base
/// module's dexes it wrote. The store's split generation preserves the base module's dex names and content, so an
/// AAB pack can predict this digest where it cannot predict the installed entry set: an edit, addition or removal
/// of any class dex changes the fold and nothing decrypts.
///
/// @param apk_path The base APK's path, as the runtime resolved it.
/// @return The 32-byte digest. Nothing when the file can't be mapped, the archive is malformed, or a class dex is
/// compressed — a store install ships dexes uncompressed, so a compressed one is not a shape the packer predicted.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_dex_digest(const std::string& apk_path);

/// Reads the observation that the installed APK set holds no unbound code or code-loading hook: no APK beside the
/// base holds a class dex (the store's config splits never do), and neither the base nor any split holds the native
/// launch wrapper the platform honours for a debuggable app. An AAB pack folds the clean fact; a split that carries
/// code, or any launch wrapper, flips the first byte, the fold comes out wrong, and nothing decrypts.
///
/// @param apk_path The base APK's path, as the runtime resolved it; its directory is the one the store installs
/// splits into.
/// @return The 32-byte block, the fact in the first byte and zeros behind it. Nothing when the install directory
/// or a sibling APK can't be read, which fails the recovery the way every unread input does.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_split_dex_flag(const std::string& apk_path);

}  // namespace rasp::android::apk
