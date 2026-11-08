/// The key schedule the packer locks the payload with: how the runtime rebuilds the root key from the app's own
/// artifacts and the environment, and derives every frame's key from it. Nothing here reads a key from anywhere:
/// there is no key in the app, only parts that combine into one.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "payload/cipher.h"

namespace rasp::android::payload {

/// A 32-byte key of the schedule: the root key, the dex master, or a frame key.
using Key = std::array<std::uint8_t, kKeySize>;

/// The environment the schedule's gates measure, as facts the caller observed.
///
/// The loader fills one in when it recovers the root key: each fact holds on a clean device, and each one that
/// doesn't changes the gate block, so the recovered root is wrong and every frame's tag fails. Nothing reports why:
/// the failure looks like a corrupt frame, the same as any other wrong input.
struct Environment {
  /// A JNI environment exists and its GetVersion reports a JNI 1.x version.
  bool java_environment = false;
  /// The process's TracerPid, from /proc/self/status, is 0.
  bool no_tracer = false;
  /// The library is loaded from a path under /data, as an installed app's is.
  bool installed_under_data = false;
};

/// The environment every clean device has, the one the packer folds into the schedule.
inline constexpr Environment kCleanEnvironment{
    .java_environment = true,
    .no_tracer = true,
    .installed_under_data = true,
};

/// The root key recovered from the parts the app ships: the library's keystore share and the bindings of its own
/// sections, the asset share from the APK, and the environment's gates.
///
/// It derives the class map's frame key; the dex master, which derives every business dex's frame key, comes from the
/// root bound to the map frame as shipped (dex_master).
///
/// @param share_lib The keystore share: the last kKeySize bytes of the library's `.rasp_config` section, as shipped.
/// @param share_asset The asset share: the bytes of the `assets/rasp/s.bin` entry.
/// @param config_binding The digest of the library's config region: the section without its trailing share.
/// @param text_binding The digest of the library's `.text` section.
/// @param gates The gate block of the observed environment.
/// @return The root key. Nothing when a part is not kKeySize bytes.
[[nodiscard]] std::optional<Key> root_key(std::span<const std::uint8_t> share_lib,
                                          std::span<const std::uint8_t> share_asset,
                                          std::span<const std::uint8_t> config_binding,
                                          std::span<const std::uint8_t> text_binding,
                                          std::span<const std::uint8_t> gates);

/// The master of every business dex's frame key: the root bound to the map frame as shipped.
///
/// The digest of the whole frame — nonce, ciphertext and tag — is folded with the root, so replacing the map breaks
/// every dex key too.
///
/// @param root The root key.
/// @param map_frame The encrypted class map, the whole frame as shipped.
/// @return The dex master. Nothing when the digest can't be computed.
[[nodiscard]] std::optional<Key> dex_master(const Key& root, std::span<const std::uint8_t> map_frame);

/// The key of one frame: HKDF-SHA256 of its stage's master, with the frame's nonce as salt and
/// `rasp.v1.frame/<entry>` as info.
///
/// The entry name in the info binds each key to the entry it decrypts, so a renamed entry no longer decrypts, and two
/// frames of one stage never share a key.
///
/// @param master The stage's master key: the root for the class map, the dex master for a business dex.
/// @param nonce The frame's nonce: the kNonceSize bytes the frame starts with.
/// @param entry The frame's full APK entry name, such as `assets/rasp/map.bin`.
/// @return The frame key. Nothing when the derivation fails.
[[nodiscard]] std::optional<Key> frame_key(const Key& master, std::span<const std::uint8_t> nonce,
                                           std::string_view entry);

/// HKDF-SHA256, as RFC 5869 defines it, of one secret with one salt and one info, to 32 bytes.
///
/// The schedule's frame keys come out of it; it is exported for the tests to check against the RFC's vectors.
///
/// @param secret The input keying material, any length.
/// @param info The context and application information, as text.
/// @param salt The salt, any length, including empty.
/// @return The 32 output bytes. Nothing when the crypto library can't run the derivation.
[[nodiscard]] std::optional<Key> hkdf_sha256(std::span<const std::uint8_t> secret, std::string_view info,
                                             std::span<const std::uint8_t> salt);

/// The gate block of an environment: one byte per fact, then zeros.
///
/// @param environment The environment the caller observed.
/// @return The block, kKeySize bytes.
[[nodiscard]] Key gate_block(const Environment& environment);

/// Recovers the root key from the app the packer produced, the way the loader does at install time.
///
/// It reads the library's own file for its `.rasp_config` and `.text` sections (util::read_library_file follows the
/// loader's path, plain or `apk!/lib/...`), reads the asset share from the APK, folds the parts with the environment's
/// gates, and gives back the root. Every input is content the app already ships: the share in the section and the
/// share in the entry cancel out with the bindings and the gates, and the root is the remainder.
///
/// @param environment The environment the loader observed.
/// @param library_path The library's path as the dynamic loader reports it.
/// @param apk The path of the app's APK, which holds the asset share.
/// @return The root key. Nothing when the library or the share entry can't be read, the sections can't be found, or
/// a digest can't be computed; the caller then serves no business class, exactly as for a corrupt APK.
[[nodiscard]] std::optional<Key> recover_root_key(const Environment& environment, std::string_view library_path,
                                                  const std::string& apk);

}  // namespace rasp::android::payload
