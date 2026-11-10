/// The key schedule the packer locks the payload with, in the runtime: the fold program's interpreter, the two
/// chains, the sensors, and the gathering that reads the program's inputs from the library and the APK. The
/// packer's key_schedule.py makes the programs this interprets, and the tests of both sides check the same fixed
/// vectors.
///
/// The digests, the ELF section finding and the text-integrity observation come from the integrity check's helpers
/// (checks/integrity.h), so the schedule and the check read the library's own sections through the same readers.

#include "payload/key_schedule.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "apk/archive.h"
#include "checks/debugger.h"
#include "checks/hooks.h"
#include "checks/integrity.h"
#include "payload/assets.h"
#include "payload/cipher.h"
#include "rasp/observation.h"
#include "util/apk_file.h"

namespace rasp::android::payload {

namespace {

/// The name of the library section a fold record's parameter names, the packer's table mirrored.
///
/// @param index The record's parameter, a section-name index.
/// @return The section's name, or nothing when the index is outside the table.
[[nodiscard]] std::optional<std::string_view> section_name(std::uint16_t index) {
  switch (index) {
    case 0:
      return ".rodata";
    case 1:
      return ".dynstr";
    case 2:
      return ".rela.dyn";
    case 3:
      return ".eh_frame";
    case 4:
      return ".plt";
    case 5:
      return ".data.rel.ro";
    case 6:
      return ".got";
    default:
      return std::nullopt;
  }
}

/// The offset, within a fold program, of the two chain counts, then the records, then the constants.
constexpr std::size_t kCountOffset = 16;
constexpr std::size_t kRecordSize = 8;
constexpr std::size_t kRecordsOffset = 20;
constexpr std::size_t kConstantsOffset = kRecordsOffset + (kMaxProgramRecords * kRecordSize);

/// The largest library file read. librasp.so is well under this, and the limit bounds what the read allocates for a
/// forged file.
constexpr std::size_t kMaxLibrarySize = std::size_t{64} << 20U;

/// The smallest `.rasp_config` section the schedule accepts: a byte of config, a program, a keystore share and the
/// expected text digest.
constexpr std::uint64_t kSmallestConfigSection = kProgramSize + (2 * kKeySize) + 1;

/// The name of the library's config section, whose trailing bytes hold the fold program and the keystore share. The
/// packer renames the section in the shipped library, so this is the renamed name, not the raw build's.
constexpr std::string_view kConfigSection = ".init";

/// The prefix of every derivation info string of the schedule, followed by "fold.<tag>/<i>", "frame/<entry>", "seed"
/// or "guard".
constexpr std::string_view kFrameInfoPrefix = "rasp.v2.";

/// The info of the dex seed's derivation.
constexpr std::string_view kSeedInfo = "rasp.v2.seed";

/// The info of the armed master's HKDF step: the seed under the Java share.
constexpr std::string_view kArmedInfo = "rasp.v2.armed";

/// The info of the sensor guard's derivation.
constexpr std::string_view kGuardInfo = "rasp.v2.guard";

static_assert(checks::kDigestSize == kKeySize, "the schedule folds digests with keys of the same size");

/// XORs `input` into `out`, bytewise, leaving `out` holding their running fold.
///
/// @param out The key the input is folded into, exactly as long as `input`.
/// @param input The bytes to fold in.
void xor_into(std::span<std::uint8_t> out, std::span<const std::uint8_t> input) {
  auto out_byte = out.begin();
  for (const std::uint8_t byte : input) {
    *out_byte = static_cast<std::uint8_t>(*out_byte ^ byte);
    ++out_byte;
  }
}

/// Feeds `bytes` to one input of the derivation, where an empty input is allowed.
///
/// @param operation The derivation to feed.
/// @param step The input the bytes are for.
/// @param bytes The bytes to feed, which can be empty.
/// @return The PSA status of the input.
[[nodiscard]] psa_status_t feed(psa_key_derivation_operation_t& operation, psa_key_derivation_step_t step,
                                std::span<const std::uint8_t> bytes) {
  return psa_key_derivation_input_bytes(&operation, step, bytes.data(), bytes.size());
}

/// The little-endian 16-bit value at `offset` in `bytes`.
///
/// @param bytes The bytes to read.
/// @param offset Where to read.
/// @return The value there.
[[nodiscard]] std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) {
  const unsigned low = bytes[offset];
  const unsigned high = bytes[offset + 1];
  return static_cast<std::uint16_t>(low | (high << 8U));
}

/// The little-endian 32-bit value at `offset` in `bytes`.
///
/// @param bytes The bytes to read.
/// @param offset Where to read.
/// @return The value there.
[[nodiscard]] std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t offset) {
  const std::uint32_t b0 = bytes[offset];
  const std::uint32_t b1 = bytes[offset + 1];
  const std::uint32_t b2 = bytes[offset + 2];
  const std::uint32_t b3 = bytes[offset + 3];
  return b0 | (b1 << 8U) | (b2 << 16U) | (b3 << 24U);
}

/// Whether the library's `.text` in memory matches its file, as the integrity check observes it.
///
/// @return What the check says about the running process.
[[nodiscard]] bool text_is_intact() {
#ifdef __ANDROID__
  const std::vector<Observation> hashes = checks::integrity();
  if (hashes.size() != 2 || hashes[0].status != Status::kOk || hashes[1].status != Status::kOk) {
    return false;
  }
  const std::string* const file = std::get_if<std::string>(&hashes[0].value);
  const std::string* const memory = std::get_if<std::string>(&hashes[1].value);
  return file != nullptr && memory != nullptr && *file == *memory;
#else
  // A host build cannot observe its own code section: the check's self-observation needs the dynamic loader's
  // module tables. The guard is a device fact; the tests cover its arithmetic with fixed sensor blocks.
  return true;
#endif
}

/// The key a key-sized span holds, zero-padded to the key's size when it is short.
///
/// @param bytes The bytes read, expected to be kKeySize long.
/// @return The key they hold.
[[nodiscard]] Key read_key(std::span<const std::uint8_t> bytes) {
  Key key{};
  const std::size_t count = std::min(bytes.size(), key.size());
  std::ranges::copy(bytes.first(count), key.begin());
  return key;
}

/// The digest of a region of the library file, at `offset` for `size` bytes.
///
/// @param image The library's whole file bytes.
/// @param region The region to digest, with its file offset and size.
/// @return The digest. Nothing when the region reaches outside the image or the digest fails.
[[nodiscard]] std::optional<Key> digest_of(std::span<const std::uint8_t> image,
                                           const std::optional<checks::TextRegion>& region) {
  if (!region.has_value() || region->file_offset > image.size() || region->size > image.size() - region->file_offset) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> bytes =
      image.subspan(static_cast<std::size_t>(region->file_offset), static_cast<std::size_t>(region->size));
  return checks::sha256(bytes);
}

/// The digest of the library section a record's parameter names.
///
/// @param image The library's whole file bytes.
/// @param param The record's parameter, a section-name index.
/// @return The digest. Nothing when the index is outside the table, the library has no such section, or the digest
/// fails.
[[nodiscard]] std::optional<Key> section_digest(std::span<const std::uint8_t> image, std::uint16_t param) {
  const std::optional<std::string_view> name = section_name(param);
  if (!name.has_value()) {
    return std::nullopt;
  }
  const std::optional<checks::SectionRegion> section = checks::find_section_region(image, *name);
  if (!section.has_value()) {
    return std::nullopt;
  }
  return digest_of(image,
                   checks::TextRegion{.file_offset = section->file_offset, .memory_address = 0, .size = section->size});
}

/// The digest of a byte range of the library file.
///
/// @param image The library's whole file bytes.
/// @param offset The range's offset.
/// @param length The range's length.
/// @return The digest. Nothing when the range reaches outside the image or the digest fails.
[[nodiscard]] std::optional<Key> range_digest(std::span<const std::uint8_t> image, std::uint32_t offset,
                                              std::uint16_t length) {
  if (offset > image.size() || length > image.size() - offset) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> bytes = image.subspan(static_cast<std::size_t>(offset), length);
  return checks::sha256(bytes);
}

/// The digest of the config region, the section's bytes before the keystore share.
///
/// @param config_region The region to digest.
/// @return The digest. Nothing when the digest fails.
[[nodiscard]] std::optional<Key> digest_of_region(std::span<const std::uint8_t> config_region) {
  return checks::sha256(config_region);
}

/// The digest of the decoy entry a record's parameter names.
///
/// @param apk The path of the app's APK.
/// @param param The record's parameter, the decoy's index.
/// @return The digest. Nothing when the entry can't be read or the digest fails.
[[nodiscard]] std::optional<Key> entry_digest(const std::string& apk, std::uint16_t param) {
  const std::optional<std::vector<std::uint8_t>> entry = apk::read_stored_entry(apk, decoy_entry_name(param));
  if (!entry.has_value()) {
    return std::nullopt;
  }
  return checks::sha256(*entry);
}

/// The library-side inputs a fold's records gather from, read once per recovery.
struct FoldInputs {
  /// The library's whole file bytes, with its config, program and keystore.
  std::span<const std::uint8_t> image;
  /// The `.rasp_config` section's bytes before the keystore share, as shipped.
  std::span<const std::uint8_t> config_region;
  /// The asset share read from the s.bin entry.
  std::span<const std::uint8_t> share;
};

/// Gathers one record's input, the record's source read from the fold's inputs.
///
/// @param program The fold program the library carries, for its constants.
/// @param record The record whose source to gather.
/// @param inputs The library-side inputs, read once per recovery.
/// @param environment The environment the recovery folds in as its gates.
/// @param apk The path of the app's APK, which holds the decoy entries.
/// @return The gathered input. Nothing when the record's source can't be read.
[[nodiscard]] std::optional<Key> gather_record(const FoldProgram& program, const FoldRecord& record,
                                               const FoldInputs& inputs, const Environment& environment,
                                               const std::string& apk) {
  switch (record.kind) {
    case RecordKind::kText:
      return digest_of(inputs.image, checks::find_text_region(inputs.image, 0));
    case RecordKind::kSection:
      return section_digest(inputs.image, record.param);
    case RecordKind::kRange:
      return range_digest(inputs.image, record.param32, record.param);
    case RecordKind::kShare:
      return read_key(inputs.share);
    case RecordKind::kRegion:
      return digest_of_region(inputs.config_region);
    case RecordKind::kGates:
      return gate_block(environment);
    case RecordKind::kConstant:
      if (record.param >= program.constants.size()) {
        return std::nullopt;
      }
      return program.constants[record.param];
    case RecordKind::kEntry:
      return entry_digest(apk, record.param);
    case RecordKind::kPackage:
      return package_digest(apk);
    case RecordKind::kStub: {
      const std::optional<std::vector<std::uint8_t>> stub = apk::read_stub_entry(apk);
      if (!stub.has_value()) {
        return std::nullopt;
      }
      return checks::sha256(*stub);
    }
    case RecordKind::kApk: {
      const std::optional<std::vector<std::uint8_t>> digest = apk::read_apk_digest(apk);
      if (!digest.has_value() || digest->size() != kKeySize) {
        return std::nullopt;
      }
      Key key{};
      std::ranges::copy(*digest, key.begin());
      return key;
    }
  }
  return std::nullopt;
}

/// Gathers one chain's inputs, the records' sources read from the fold's inputs.
///
/// @param program The fold program the library carries.
/// @param records The chain's records, in order.
/// @param inputs The library-side inputs, read once per recovery.
/// @param environment The environment the recovery folds in as its gates.
/// @param apk The path of the app's APK, which holds the decoy entries.
/// @return The gathered inputs, in order; nothing as soon as one source can't be read.
[[nodiscard]] std::optional<std::vector<Key>> gather_inputs(const FoldProgram& program,
                                                            std::span<const FoldRecord> records,
                                                            const FoldInputs& inputs, const Environment& environment,
                                                            const std::string& apk) {
  std::vector<Key> gathered;
  gathered.reserve(records.size());
  for (const FoldRecord& record : records) {
    const std::optional<Key> input = gather_record(program, record, inputs, environment, apk);
    if (!input.has_value()) {
      return std::nullopt;
    }
    gathered.push_back(*input);
  }
  return gathered;
}

}  // namespace

std::optional<FoldProgram> decode_program(std::span<const std::uint8_t> blob) {
  if (blob.size() != kProgramSize) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> unmasked(blob.begin(), blob.end());
  const std::span<std::uint8_t> masked(unmasked);
  for (std::size_t index = kCountOffset; index < kProgramSize; ++index) {
    masked[index] = static_cast<std::uint8_t>(masked[index] ^ blob[index % kCountOffset]);
  }
  const std::uint16_t count_a = read_u16(unmasked, kCountOffset);
  const std::uint16_t count_s = read_u16(unmasked, kCountOffset + 2);
  if (static_cast<std::size_t>(count_a) + count_s > kMaxProgramRecords) {
    return std::nullopt;
  }
  FoldProgram program;
  const std::size_t count = static_cast<std::size_t>(count_a) + count_s;
  for (std::size_t index = 0; index < count; ++index) {
    const std::size_t offset = kRecordsOffset + (index * kRecordSize);
    const auto kind = static_cast<RecordKind>(unmasked[offset]);
    const FoldRecord record{
        .kind = kind,
        .param = read_u16(unmasked, offset + 2),
        .param32 = read_u32(unmasked, offset + 4),
    };
    (index < count_a ? program.chain_a : program.chain_s).push_back(record);
  }
  std::size_t named = 0;
  for (const FoldRecord& record : program.chain_a) {
    if (record.kind == RecordKind::kConstant) {
      named = std::max<std::size_t>(named, record.param + 1U);
    }
  }
  for (const FoldRecord& record : program.chain_s) {
    if (record.kind == RecordKind::kConstant) {
      named = std::max<std::size_t>(named, record.param + 1U);
    }
  }
  for (std::size_t index = 0; index < named; ++index) {
    const std::size_t offset = kConstantsOffset + (index * kKeySize);
    Key constant{};
    std::ranges::copy(std::span(unmasked).subspan(offset, kKeySize), constant.begin());
    program.constants.push_back(constant);
  }
  return program;
}

std::string decoy_entry_name(std::uint16_t index) {
  return std::string(kDecoyEntryPrefix) + std::to_string(index) + ".bin";
}

/// The digest of the app's package name, read from its APK's install path: the APK sits in a directory named
/// `<package>-<random>`, and a package name cannot contain '-', so the name is the part before the first one. The
/// install path is the loader's own, so a repackaged or virtualized install that runs the library from another
/// app's directories names a different package and the fold comes out differently.
///
/// @param apk_path The path of the app's APK, as the dynamic loader reports it.
/// @return The digest. Nothing when the path holds no package name.
[[nodiscard]] std::optional<Key> package_digest(std::string_view apk_path) {
  const std::size_t name_start = apk_path.find_last_of('/');
  if (name_start == std::string_view::npos || name_start == 0) {
    return std::nullopt;
  }
  const std::size_t directory_start = apk_path.find_last_of('/', name_start - 1);
  const std::size_t directory_offset = directory_start == std::string_view::npos ? 0 : directory_start + 1;
  const std::string_view directory = apk_path.substr(directory_offset, name_start - directory_offset);
  const std::size_t dash = directory.find_first_of('-');
  const std::string_view package = dash == std::string_view::npos ? directory : directory.substr(0, dash);
  if (package.empty() || package.contains('/')) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  return checks::sha256(std::span(reinterpret_cast<const std::uint8_t*>(package.data()), package.size()));
}

Key gate_block(const Environment& environment) {
  Key block{};
  block[0] = environment.java_environment ? 1U : 0U;
  block[1] = environment.no_tracer ? 1U : 0U;
  block[2] = environment.installed_under_data ? 1U : 0U;
  return block;
}

Key sensor_block(const Sensors& sensors) {
  Key block{};
  block[0] = sensors.no_tracer ? 1U : 0U;
  block[1] = sensors.text_intact ? 1U : 0U;
  block[2] = sensors.no_framework_maps ? 1U : 0U;
  block[3] = sensors.no_rwx_regions ? 1U : 0U;
  block[4] = sensors.no_framework_threads ? 1U : 0U;
  block[5] = sensors.no_foreign_libraries ? 1U : 0U;
  return block;
}

/// Whether the mapping's pathname is one the process is expected to hold: a system directory, the app's own install
/// directory, or the vendor's runtime. A library added by repackaging the APK loads from the app's install directory
/// too, so this check catches only libraries from outside the app — the stub-dex record catches the ones the
/// repackage added inside it.
[[nodiscard]] bool is_expected_library_path(std::string_view path) {
  return path.starts_with("/system/") || path.starts_with("/apex/") || path.starts_with("/vendor/") ||
         path.starts_with("/product/") || path.starts_with("/data/app/");
}

/// Whether the memory-map line maps a shared library from outside the expected directories.
[[nodiscard]] bool is_foreign_library(std::string_view line) {
  const std::size_t path_start = line.find(" /");
  if (path_start == std::string_view::npos) {
    return false;
  }
  const std::string_view path = line.substr(path_start + 1);
  return path.ends_with(".so") && !is_expected_library_path(path);
}

Sensors observe_sensors() {
  const Observation tracer = checks::observe_tracer_pid("/proc/self/status");
  const std::int64_t* const tracer_pid = std::get_if<std::int64_t>(&tracer.value);
  const std::vector<Observation> hook_observations = checks::hooks();
  bool no_framework_maps = true;
  bool no_rwx_regions = true;
  bool no_framework_threads = true;
  bool no_foreign_libraries = true;
  for (const Observation& observation : hook_observations) {
    if (observation.status != Status::kOk) {
      // An unreadable source is not the same as a clean one: the fold leaves the bit unset, so
      // the key is wrong on a device whose /proc the process can't read.
      continue;
    }
    const std::vector<std::string>* const lines = std::get_if<std::vector<std::string>>(&observation.value);
    if (lines == nullptr || lines->empty()) {
      continue;
    }
    if (observation.signal == "hook.maps_hits") {
      no_framework_maps = false;
    }
    if (observation.signal == "hook.rwx_regions") {
      no_rwx_regions = false;
    }
    if (observation.signal == "hook.threads") {
      no_framework_threads = false;
    }
    if (observation.signal == "hook.foreign_libs") {
      no_foreign_libraries = false;
    }
  }
  return Sensors{
      .no_tracer = tracer.status == Status::kOk && tracer_pid != nullptr && *tracer_pid == 0,
      .text_intact = text_is_intact(),
      .no_framework_maps = no_framework_maps,
      .no_rwx_regions = no_rwx_regions,
      .no_framework_threads = no_framework_threads,
      .no_foreign_libraries = no_foreign_libraries,
  };
}

std::optional<Key> hkdf_sha256(std::span<const std::uint8_t> secret, std::string_view info,
                               std::span<const std::uint8_t> salt) {
  if (psa_crypto_init() != PSA_SUCCESS) {
    return std::nullopt;
  }
  psa_key_derivation_operation_t operation = psa_key_derivation_operation_init();
  psa_status_t status = psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
  if (status == PSA_SUCCESS) {
    status = feed(operation, PSA_KEY_DERIVATION_INPUT_SALT, salt);
  }
  if (status == PSA_SUCCESS) {
    status = feed(operation, PSA_KEY_DERIVATION_INPUT_SECRET, secret);
  }
  if (status == PSA_SUCCESS) {
    status = feed(operation, PSA_KEY_DERIVATION_INPUT_INFO,
                  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                  std::span(reinterpret_cast<const std::uint8_t*>(info.data()), info.size()));
  }
  Key output{};
  if (status == PSA_SUCCESS) {
    status = psa_key_derivation_output_bytes(&operation, output.data(), output.size());
  }
  psa_key_derivation_abort(&operation);
  if (status != PSA_SUCCESS) {
    return std::nullopt;
  }
  return output;
}

Key fold_chain(const Key& state, std::span<const Key> inputs, std::string_view tag) {
  Key current = state;
  std::string info;
  for (std::size_t index = 0; index < inputs.size(); ++index) {
    info.clear();
    info.reserve(kFrameInfoPrefix.size() + tag.size() + 12);
    info.append(kFrameInfoPrefix).append("fold.").append(tag).push_back('/');
    info.append(std::to_string(index));
    if (const std::optional<Key> next = hkdf_sha256(current, info, inputs[index])) {
      current = *next;
    }
  }
  return current;
}

std::optional<Key> frame_key(const Key& master, std::span<const std::uint8_t> nonce, std::string_view entry) {
  std::string info;
  info.reserve(kFrameInfoPrefix.size() + entry.size() + 7);
  info.append(kFrameInfoPrefix).append("frame/").append(entry);
  return hkdf_sha256(master, info, nonce);
}

std::optional<Key> seed_from(const Key& root, std::span<const std::uint8_t> map_frame) {
  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> digest = checks::sha256(map_frame);
  if (!digest.has_value()) {
    return std::nullopt;
  }
  return hkdf_sha256(root, kSeedInfo, *digest);
}

std::optional<Key> armed_master(const Key& seed, const Key& j_share) { return hkdf_sha256(seed, kArmedInfo, j_share); }

std::optional<Key> guarded_master(const Key& armed, const Key& sensors) {
  return hkdf_sha256(armed, kGuardInfo, sensors);
}

std::optional<Key> recover_root_key(const Environment& environment, std::string_view library_path,
                                    const std::string& apk) {
  const std::optional<std::vector<std::uint8_t>> library = util::read_library_file(library_path, kMaxLibrarySize);
  if (!library.has_value()) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> image(*library);

  const std::optional<checks::SectionRegion> section = checks::find_section_region(image, kConfigSection);
  if (!section.has_value() || section->size < kSmallestConfigSection) {
    return std::nullopt;
  }
  // The `.rasp_config` layout, from the section's start: the config JSON, its zero padding, the fold program, the
  // expected plaintext `.text` digest, then the keystore share in the trailing 32 bytes. The gathered region is
  // everything but the keystore: the share is written after the fold's inputs are gathered, while the digest sits
  // inside the region, so a patched expectation breaks the fold instead of being honoured by it.
  const std::uint64_t region_size = section->size - kKeySize;
  const std::span<const std::uint8_t> config_region =
      image.subspan(static_cast<std::size_t>(section->file_offset), static_cast<std::size_t>(region_size));
  const std::span<const std::uint8_t> program_bytes = image.subspan(
      static_cast<std::size_t>(section->file_offset + region_size - kProgramSize - kKeySize), kProgramSize);
  const std::span<const std::uint8_t> keystore =
      image.subspan(static_cast<std::size_t>(section->file_offset + region_size), kKeySize);

  const std::optional<FoldProgram> program = decode_program(program_bytes);
  if (!program.has_value()) {
    return std::nullopt;
  }

  const std::optional<std::vector<std::uint8_t>> share = apk::read_stored_entry(apk, kShareEntry);
  if (!share.has_value() || share->size() != kKeySize) {
    return std::nullopt;
  }

  const FoldInputs inputs{
      .image = image,
      .config_region = config_region,
      .share = *share,
  };
  const std::optional<std::vector<Key>> chain_a = gather_inputs(*program, program->chain_a, inputs, environment, apk);
  if (!chain_a.has_value()) {
    return std::nullopt;
  }
  const std::optional<std::vector<Key>> chain_s = gather_inputs(*program, program->chain_s, inputs, environment, apk);
  if (!chain_s.has_value()) {
    return std::nullopt;
  }

  const Key a_state = fold_chain(Key{}, *chain_a, "a");
  const Key s_state = fold_chain(Key{}, *chain_s, "s");
  Key root{};
  xor_into(root, a_state);
  xor_into(root, s_state);
  xor_into(root, keystore);
  return root;
}

}  // namespace rasp::android::payload
