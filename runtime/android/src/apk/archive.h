/// Reading an APK straight from its bytes, without inflating anything: an uncompressed entry, and the certificate of
/// the key that signed it.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
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

/// Reads a digest over every entry of the APK, stored or deflated: each entry's name, compression method, CRC-32 and
/// uncompressed size, and a stored entry's content too. It leaves out the entries the signing step adds (`META-INF/`),
/// the fold's own outputs (`assets/rasp/`, `assets/business/`), and the runtime's own library, matched by its filename
/// (chain A already covers its bytes). The key schedule folds this digest into the root key, so a repackaged APK that
/// edits any dex, the manifest, a resource, or adds any library derives a different key and nothing decrypts.
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

/// Reads the semantic digest of the installed base APK's manifest: every attribute of the `<manifest>` and
/// `<application>` elements except the volatile build-stamped names, canonicalised and sorted — the same digest the
/// packer computes over the protobuf manifest it wrote into the AAB. A repack that adds, removes or changes any
/// sealed attribute — a shared user id, a debuggable flag, a process name — changes the digest.
///
/// @param apk_path The base APK's path, as the runtime resolved it.
/// @return The 32-byte digest. Nothing when the manifest is absent, compressed, malformed, or holds an attribute
/// that does not canonicalise, which fails the recovery the way every unread input does.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_manifest_semantics(const std::string& apk_path);

/// Reads the digest over the installed base APK's signing certificate: the concatenated DER certificates of the
/// first v3 or v2 scheme signer, hashed once. The packer folds the digest of the developer's pinned certificate;
/// a re-signed install — or one whose companion packages are admitted under a different certificate — derives a
/// different digest and nothing decrypts.
///
/// @param apk_path The base APK's path, as the runtime resolved it.
/// @return The 32-byte digest. Nothing when the APK holds no APK signing block with a v3 or v2 scheme pair, which
/// fails the recovery the way every unread input does.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_signer_digest(const std::string& apk_path);
/// Finds the certificate of the key that Android uses as the signer of the APK whose bytes are `apk`, on a device at
/// `api_level`.
///
/// An APK signed with the v2 or v3 scheme carries an APK Signing Block right before its central directory. Its entries
/// are read as Android verifies them, newest first: the v3.1 entry, which holds the signers of a rotated key and is
/// read only on Android 13 and up, where the platform honors it, then the v3 entry, then the v2 entry. A v3 or v3.1
/// signer applies to a range of API levels, and the first one whose range holds `api_level` is used; v2's first signer
/// applies to every level. This returns that signer's first certificate, the X.509 certificate in DER whose digest
/// `apksigner verify --print-certs` prints. It doesn't check the signature: Android checked it when the app was
/// installed.
///
/// @param apk The bytes of the APK.
/// @param api_level The API level of the device.
/// @return The certificate's DER bytes. Nothing when the APK has no end-of-central-directory record or no APK Signing
/// Block, as an APK signed only with the JAR scheme, no entry has a signer for `api_level`, a length runs past what
/// holds it, or the certificate is empty or larger than 64 KiB.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> find_signing_certificate(std::span<const std::uint8_t> apk,
                                                                                std::uint32_t api_level);

/// Reads the certificate of the key that Android uses as the signer of the APK at `apk_path`, as
/// find_signing_certificate finds it.
///
/// @param apk_path The APK file to read.
/// @param api_level The API level of the device.
/// @return The certificate's DER bytes. Nothing when the file can't be mapped, or find_signing_certificate finds none.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_signing_certificate(const std::string& apk_path,
                                                                                std::uint32_t api_level);

}  // namespace rasp::android::apk
