/// The key schedule the packer locks the payload with: two order-sensitive HKDF chains over the app's own artifacts
/// and the environment, their recipe written as a per-app fold program in the library's `.rasp_config` section, and
/// a sensor guard that re-observes the process on every decryption. Nothing here reads a key from anywhere: there
/// is no key in the app, only parts that combine into one.

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

/// A 32-byte key of the schedule: the root key, a chain state, a frame key, or a sensor block.
using Key = std::array<std::uint8_t, kKeySize>;

/// The environment the schedule's gates measure, as facts the caller observed, folded into the recovery as one chain
/// input. Each fact holds on a clean device; each one that doesn't changes the fold, so the recovered root key is
/// wrong and every frame's tag fails, with no branch anywhere that says why.
struct Environment {
  /// A JNI environment exists and its GetVersion reports a JNI 1.x version.
  bool java_environment = false;
  /// The process's TracerPid, from /proc/self/status, is 0.
  bool no_tracer = false;
  /// The library is loaded from a path under /data, as an installed app's is.
  bool installed_under_data = false;
};

/// The environment every clean device has, the one the packer folds into the fold program's gates input.
inline constexpr Environment kCleanEnvironment{
    .java_environment = true,
    .no_tracer = true,
    .installed_under_data = true,
};

/// The state of the process the sensor guard measures, re-observed on every decryption and folded into the dex keys.
///
/// A debugger attached between loads, a hook patched into the library's code, an instrumentation framework's mapping
/// or thread, or a writable-executable region the app didn't make, flips a fact, and the next decryption derives a
/// wrong key: the frame's tag fails, with no branch anywhere that says why.
struct Sensors {
  /// The process's TracerPid, from /proc/self/status, is 0.
  bool no_tracer = false;
  /// The library's `.text` in memory matches its file, as the integrity check observes it.
  bool text_intact = false;
  /// No mapping in the process's memory map names a known instrumentation framework.
  bool no_framework_maps = false;
  /// No mapping in the process's memory map is both writable and executable.
  bool no_rwx_regions = false;
  /// No thread of the process carries the name a hooking framework gives its own threads.
  bool no_framework_threads = false;
  /// No shared library is loaded from outside the system's own and the app's own directories. A library injected
  /// by repackaging the APK — even one with an ordinary name — loads from a path this check sees.
  bool no_foreign_libraries = false;
};

/// The sensor block of a clean process: no tracer, the library's code intact, no framework mapping, no
/// writable-executable memory, no framework-named thread, no library from outside the expected directories.
inline constexpr Key kCleanSensors{{1U, 1U, 1U, 1U, 1U, 1U}};

/// The size of the fold program, in bytes: the masked recipe the packer writes into the library's `.rasp_config`
/// section, between the config's zero padding and the keystore share.
inline constexpr std::size_t kProgramSize = 512;

/// The most records one fold program can hold, across both chains.
inline constexpr std::size_t kMaxProgramRecords = 16;

/// The source one fold record gathers its input from.
enum class RecordKind : std::uint8_t {
  /// The digest of the library's `.text`, chain A.
  kText = 0,
  /// The digest of a named library section, chain A.
  kSection = 1,
  /// The digest of a byte range of the library file, chain A.
  kRange = 2,
  /// The asset share, the `assets/rasp/s.bin` entry, chain S.
  kShare = 3,
  /// The digest of the config region, chain S.
  kRegion = 4,
  /// The gate block of the observed environment, chain S.
  kGates = 5,
  /// One of the program's own constants, chain S.
  kConstant = 6,
  /// The digest of a decoy entry, `assets/rasp/r<i>.bin`, chain S.
  kEntry = 7,
  /// The digest of the app's package name, as its APK's install path names it, chain S.
  kPackage = 8,
  /// The digest of the stub dex, the highest-numbered `classesN.dex` entry, chain S. A repackaged APK whose stub was
  /// edited to load extra code derives a different key.
  kStub = 9,
  /// The digest over every stored entry of the APK, excluding signing artifacts, fold outputs and the runtime's own
  /// library, chain S. A repackaged APK that edits any dex, the manifest, a resource, or adds any library derives
  /// a different key.
  kApk = 10,
};

/// One step of a fold chain: a source to gather and fold in as the step's salt.
struct FoldRecord {
  /// The source the record names.
  RecordKind kind = RecordKind::kText;
  /// The 16-bit parameter: a section-name index, a constant index, a range length or a decoy-entry index.
  std::uint16_t param = 0;
  /// The 32-bit parameter: a range's offset in the library file.
  std::uint32_t param32 = 0;
};

/// A decoded fold program: the two chains' records, in order, and the constants a record can name.
struct FoldProgram {
  /// Chain A's records: the library's own content.
  std::vector<FoldRecord> chain_a;
  /// Chain S's records: the shared artifacts and the environment.
  std::vector<FoldRecord> chain_s;
  /// The 32-byte constants a kConstant record names by index.
  std::vector<Key> constants;
};

/// Decodes a fold program from its bytes, as the packer wrote them into the library's section.
///
/// The program holds the mask in its first 16 bytes, then the two counts, then the records, then the constants, each
/// byte after the mask XORed with the mask at its position.
///
/// @param blob The program's kProgramSize bytes.
/// @return The program, with only the constants its records name. Nothing when the blob is the wrong size or names
/// more records than fit.
[[nodiscard]] std::optional<FoldProgram> decode_program(std::span<const std::uint8_t> blob);

/// The APK entry name of the decoy a record's parameter names.
///
/// @param index The record's parameter, the decoy's index.
/// @return The entry name, `assets/rasp/r<index>.bin`.
[[nodiscard]] std::string decoy_entry_name(std::uint16_t index);

/// The digest of the app's package name, as its APK's install path names it: the directory the APK sits in is
/// `<package>-<random>`, and a package name cannot contain '-', so the name is the part before the first one. A
/// repackaged or virtualized install that runs the library from another app's directories names a different
/// package, and the fold that folds this digest in comes out differently.
///
/// @param apk_path The path of the app's APK, as the dynamic loader reports it.
/// @return The digest. Nothing when the path holds no package name.
[[nodiscard]] std::optional<Key> package_digest(std::string_view apk_path);

/// The gate block of an environment: one byte per fact, then zeros.
///
/// @param environment The environment the caller observed.
/// @return The block, kKeySize bytes.
[[nodiscard]] Key gate_block(const Environment& environment);

/// The sensor block of a process: one byte per fact, then zeros.
///
/// @param sensors The sensors observed now.
/// @return The block, kKeySize bytes.
[[nodiscard]] Key sensor_block(const Sensors& sensors);

/// Observes the process's sensors, the way every decryption does.
///
/// Reads the tracer from /proc/self/status and compares the library's `.text` in memory against its file, through
/// the integrity check. On a host build the text sensor cannot run — the check's self-observation needs the dynamic
/// loader's module tables — and reads as intact: the guard is a device fact, and the host tests cover its arithmetic
/// with fixed sensor blocks.
///
/// @return What the process looks like right now.
[[nodiscard]] Sensors observe_sensors();

/// HKDF-SHA256, as RFC 5869 defines it, of one secret with one salt and one info, to 32 bytes.
///
/// @param secret The input keying material, any length.
/// @param info The context and application information, as text.
/// @param salt The salt, any length, including empty.
/// @return The 32 output bytes. Nothing when the crypto library can't run the derivation.
[[nodiscard]] std::optional<Key> hkdf_sha256(std::span<const std::uint8_t> secret, std::string_view info,
                                             std::span<const std::uint8_t> salt);

/// Folds `inputs` into `state`, one HKDF step per input, in order.
///
/// Each step derives the next state from the current one, with the input as the step's salt and the position in the
/// info, so the chain is order-sensitive: reordering, dropping or adding a step changes the result.
///
/// @param state The state to start from, usually zeroed.
/// @param inputs The chain's gathered inputs, in the records' order.
/// @param tag The chain's tag, "a" or "s", which goes into each step's info.
/// @return The chain's final state.
[[nodiscard]] Key fold_chain(const Key& state, std::span<const Key> inputs, std::string_view tag);

/// The key of one frame: HKDF-SHA256 of its stage's master, with the frame's nonce as salt and
/// `rasp.v2.frame/<entry>` as info.
///
/// @param master The stage's master key: the root for the class map, the guarded master for a business dex.
/// @param nonce The frame's nonce: the kNonceSize bytes the frame starts with.
/// @param entry The frame's full APK entry name, such as `assets/rasp/map.bin`.
/// @return The frame key. Nothing when the derivation fails.
[[nodiscard]] std::optional<Key> frame_key(const Key& master, std::span<const std::uint8_t> nonce,
                                           std::string_view entry);

/// The dex seed: the root bound to the map frame as shipped.
///
/// @param root The root key.
/// @param map_frame The encrypted class map, the whole frame as shipped.
/// @return The seed. Nothing when the digest can't be computed.
[[nodiscard]] std::optional<Key> seed_from(const Key& root, std::span<const std::uint8_t> map_frame);

/// The armed master: the seed under the Java share the stub's program produced on the real runtime.
///
/// The share comes from a per-app program of resolution steps the stub executes through ART (the j.bin entry), so
/// this master needs the native fold *and* a runtime that resolves the program's classes the way the packer
/// predicted. An emulated runtime that answers one step differently derives a different master, and every dex
/// frame's tag fails, with no branch anywhere that says why.
///
/// @param seed The dex seed.
/// @param j_share The Java share the stub produced.
/// @return The armed master. Nothing when the derivation fails.
[[nodiscard]] std::optional<Key> armed_master(const Key& seed, const Key& j_share);

/// The master of the next decryption: the armed master under the observed sensor guard.
///
/// @param armed The armed master the Java share produced.
/// @param sensors The sensor block observed now.
/// @return The guarded master. Nothing when the derivation fails.
[[nodiscard]] std::optional<Key> guarded_master(const Key& armed, const Key& sensors);

/// Recovers the root key from the app the packer produced, the way the loader does at install time.
///
/// It reads the library's own file for its `.init` section: the config region, the fold program and the
/// keystore share. It decodes the program, gathers every input the program names — the `.text` digest, the named
/// sections and ranges, the s.bin entry, the config region digest, the environment's gates, the program's constants,
/// the decoy entries and the app's package name — runs the two chains, and folds the keystore share in: the share
/// is what the packer wrote to cancel its ABI's chains, so the result is the root.
///
/// @param environment The environment the loader observed.
/// @param library_path The library's path as the dynamic loader reports it.
/// @param apk The path of the app's APK, which holds the asset share, the decoy entries and, in its install path,
/// the package name.
/// @return The root key. Nothing when the library, the share entry or any input the program names can't be read; the
/// caller then serves no business class, exactly as for a corrupt APK.
[[nodiscard]] std::optional<Key> recover_root_key(const Environment& environment, std::string_view library_path,
                                                  const std::string& apk);

}  // namespace rasp::android::payload
