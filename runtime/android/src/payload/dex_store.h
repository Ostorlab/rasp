/// The dex store: an index of the packer's class map, and the reads and decryption that turn a class name into the
/// decrypted dex that defines it, under the key schedule's sensor guard.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "payload/key_schedule.h"

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
/// A caller builds one with open_dex_store and keeps it read-only for the life of the process, except for the one
/// arm call that turns the seed into the armed master. Every function here can be called from several threads at
/// once: nothing changes the store after it is armed, and decrypt is thread-safe.
struct DexStore {
  /// The path of the APK that holds the encrypted dexes.
  std::string apk;
  /// The master of every business dex's frame key before the Java share and the guard: the root key bound to the
  /// map frame as shipped. It never decrypts a frame by itself: the stub must arm the store first.
  Key seed{};
  /// The Java program the packer shipped, decrypted: the steps the stub executes through the real runtime to
  /// produce the share that arms the store. Empty when the app packs without one.
  std::vector<std::uint8_t> j_program;
  /// The armed master, once the stub's share arrived: the seed under the Java share. Nothing until arm_j_store
  /// succeeds, and no dex decrypts before it does.
  std::optional<Key> armed;
  /// Every dex the map names, each with its APK entry name and its classes.
  std::vector<EncryptedDex> dexes;
  /// The index into `dexes` of the dex that defines each class, by binary class name.
  std::unordered_map<std::string, std::size_t> dex_of_class;
};

/// Builds a dex store from the app's own APK.
///
/// It reads the encrypted class map from the APK, derives its frame key from `root` and its nonce, decrypts and
/// indexes it, and keeps the dex master — `root` bound to the map frame as shipped — for the dexes. It also reads
/// the encrypted Java program, and keeps its plaintext steps for the stub to run: the loader hands them to the
/// stub, the stub executes them through the real runtime and returns the share, and arm_j_store folds that share
/// into the dex master. Each map line is `binary.class.Name,<path>`, where `<path>` is a dex's path under
/// kAssetPrefix. A line with no comma, nothing before the comma, or nothing after it is skipped. When a class is
/// on more than one line, the first line decides its dex, and the class is listed only under that dex. The
/// decrypted map is wiped once it is indexed.
///
/// @param apk The path of the APK to read the map and, later, the dexes from. It is kept in the returned store.
/// @param root The root key recovered from the schedule (key_schedule.h).
/// @return The store. Nothing when the map entry is absent or does not decrypt, in which case no class can be served.
/// The Java program may be absent — an app the packer built without one — and the store then arms from a zero share.
[[nodiscard]] std::optional<DexStore> open_dex_store(std::string apk, const Key& root);

/// Arms the store with the share the stub's Java program produced, and lets the dexes decrypt.
///
/// The share is what the packer predicted the program's steps yield on a real runtime; the armed master is the
/// seed under it, and every dex frame's key derives from the armed master and the sensors observed then. A wrong
/// share — an emulated runtime that resolves a step differently — arms just as quietly, and every frame's tag
/// fails. The stub arms once, before any business class loads; nothing decrypts before it does.
///
/// @param store The store to arm.
/// @param j_share The share the stub produced, or an all-zero key when the app shipped no program.
void arm_j_store(DexStore& store, const Key& j_share);

/// The dex that defines `class_name`, or null when no dex in the store defines it.
///
/// @param store The store to look in.
/// @param class_name The binary name of the class.
/// @return A pointer into `store`, valid while `store` lives, or null when the store has no such class.
[[nodiscard]] const EncryptedDex* dex_of(const DexStore& store, const std::string& class_name);

/// Reads and decrypts `dex`, under the sensor guard.
///
/// It reads the dex's entry from the APK, observes the process's sensors, and derives its frame key from the
/// store's armed master, the observed sensor guard, the frame's nonce and the entry's own name. A clean process on
/// a real runtime folds the same block every time; a debugger attached between loads, a hook patched into the
/// library's code, or a share that did not come from the runtime the packer predicted folds a different one, and
/// the frame's tag fails, with no branch anywhere that says why. It decrypts on every call; the caller caches the
/// result when it wants to, and wipes it once it has handed the dex to the class loader.
///
/// @param store The store `dex` came from, which holds the APK path and the armed master.
/// @param dex A dex that dex_of returned for `store`.
/// @return The decrypted dex bytes. Nothing when the store is not armed, the entry can't be read, a sensor
/// observation fails, or the frame does not decrypt. Since the packer writes every dex the map names, encrypted
/// under the schedule, nothing means the APK was changed or the process was tampered with; the caller can treat it
/// as a signal.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> decrypt_dex(const DexStore& store, const EncryptedDex& dex);

}  // namespace rasp::android::payload
