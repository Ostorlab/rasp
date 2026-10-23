/// The dex store: an index of the packer's class map, and the reads and decryption that turn a class name into the
/// decrypted dex that defines it.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace rasp::android::payload {

/// One encrypted dex the packer split out: where it lives in the APK, and the classes it defines.
struct EncryptedDex {
  /// The dex's full APK entry name: kAssetPrefix followed by the `<path>` the map gives for it.
  std::string entry;
  /// The binary names of the classes the dex defines, in the order the map lists them. A caller that loads the dex can
  /// attribute all of them to one loader at once, so the dex is decrypted only the first time any of them is needed.
  std::vector<std::string> classes;
};

/// The packer's class map, indexed for lookup, together with what a later per-dex decryption needs.
///
/// A caller builds one with open_dex_store and keeps it read-only for the life of the process. Every function here can
/// be called from several threads at once: nothing changes the store after it is built, and decrypt is thread-safe.
struct DexStore {
  /// The path of the APK that holds the encrypted dexes.
  std::string apk;
  /// The key that decrypts every dex, exactly kKeySize bytes.
  std::vector<std::uint8_t> key;
  /// Every dex the map names, each with its APK entry name and its classes.
  std::vector<EncryptedDex> dexes;
  /// The index into `dexes` of the dex that defines each class, by binary class name.
  std::unordered_map<std::string, std::size_t> dex_of_class;
};

/// Builds a dex store from the app's own APK.
///
/// It reads the encrypted class map from the APK, decrypts it with `key`, and indexes it. Each map line is
/// `binary.class.Name,<path>`, where `<path>` is a dex's path under kAssetPrefix. A line with no comma, nothing before
/// the comma, or nothing after it is skipped. When a class is on more than one line, the first line decides its dex,
/// and the class is listed only under that dex.
///
/// @param apk The path of the APK to read the map and, later, the dexes from. It is kept in the returned store.
/// @param key The key that decrypts the map and every dex. It is copied into the returned store.
/// @return The store. Nothing when the map entry is absent or does not decrypt, in which case no class can be served.
[[nodiscard]] std::optional<DexStore> open_dex_store(std::string apk, std::span<const std::uint8_t> key);

/// The dex that defines `class_name`, or null when no dex in the store defines it.
///
/// @param store The store to look in.
/// @param class_name The binary name of the class.
/// @return A pointer into `store`, valid while `store` lives, or null when the store has no such class.
[[nodiscard]] const EncryptedDex* dex_of(const DexStore& store, const std::string& class_name);

/// Reads and decrypts `dex`.
///
/// It reads the dex's entry from the APK and decrypts it, on every call; the caller caches the result when it wants to.
///
/// @param store The store `dex` came from, which holds the APK path and the key.
/// @param dex A dex that dex_of returned for `store`.
/// @return The decrypted dex bytes. Nothing when the entry can't be read or does not decrypt. Since the packer writes
/// every dex the map names, encrypted under the key, nothing means the APK was changed; the caller can treat it as a
/// signal.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> decrypt_dex(const DexStore& store, const EncryptedDex& dex);

}  // namespace rasp::android::payload
