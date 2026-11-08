/// The key schedule the packer locks the payload with, in the runtime: the fold that rebuilds the root key from the
/// app's own parts, the HKDF that gives every frame its key, and the gathering that reads the parts from the library
/// and the APK. The fold's pieces are the ones key_schedule.py on the packer's side combines, and the tests of both
/// sides check the same fixed vectors.
///
/// The digests and the ELF section finding come from the integrity check's helpers (checks/integrity.h), so the
/// schedule and the check read the library's `.text` through the same reader.

#include "payload/key_schedule.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "apk/archive.h"
#include "checks/integrity.h"
#include "payload/assets.h"
#include "payload/cipher.h"
#include "util/apk_file.h"

namespace rasp::android::payload {

namespace {

/// The HKDF info every frame key starts with, followed by the frame's full APK entry name.
constexpr std::string_view kFrameInfoPrefix = "rasp.v1.frame/";

/// The name of the library's config section, whose trailing kKeySize bytes hold the keystore share.
constexpr std::string_view kConfigSection = ".rasp_config";

/// The largest library file read. librasp.so is well under this, and the limit bounds what the read allocates for a
/// forged file.
constexpr std::size_t kMaxLibrarySize = std::size_t{64} << 20U;

/// The smallest `.rasp_config` section the schedule accepts: one byte of config region and a full keystore share.
constexpr std::uint64_t kSmallestConfigSection = kKeySize + 1;

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

}  // namespace

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

Key gate_block(const Environment& environment) {
  Key block{};
  block[0] = environment.java_environment ? 1U : 0U;
  block[1] = environment.no_tracer ? 1U : 0U;
  block[2] = environment.installed_under_data ? 1U : 0U;
  return block;
}

std::optional<Key> root_key(std::span<const std::uint8_t> share_lib, std::span<const std::uint8_t> share_asset,
                            std::span<const std::uint8_t> config_binding, std::span<const std::uint8_t> text_binding,
                            std::span<const std::uint8_t> gates) {
  if (share_lib.size() != kKeySize || share_asset.size() != kKeySize || config_binding.size() != kKeySize ||
      text_binding.size() != kKeySize || gates.size() != kKeySize) {
    return std::nullopt;
  }
  Key root{};
  xor_into(root, share_lib);
  xor_into(root, share_asset);
  xor_into(root, config_binding);
  xor_into(root, text_binding);
  xor_into(root, gates);
  return root;
}

std::optional<Key> dex_master(const Key& root, std::span<const std::uint8_t> map_frame) {
  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> digest = checks::sha256(map_frame);
  if (!digest.has_value()) {
    return std::nullopt;
  }
  Key master = root;
  xor_into(master, *digest);
  return master;
}

std::optional<Key> frame_key(const Key& master, std::span<const std::uint8_t> nonce, std::string_view entry) {
  std::string info;
  info.reserve(kFrameInfoPrefix.size() + entry.size());
  info.append(kFrameInfoPrefix).append(entry);
  return hkdf_sha256(master, info, nonce);
}

std::optional<Key> recover_root_key(const Environment& environment, std::string_view library_path,
                                    const std::string& apk) {
  const std::optional<std::vector<std::uint8_t>> library = util::read_library_file(library_path, kMaxLibrarySize);
  if (!library.has_value()) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> image(*library);

  const std::optional<checks::SectionRegion> config = checks::find_section_region(image, kConfigSection);
  if (!config.has_value() || config->size < kSmallestConfigSection) {
    return std::nullopt;
  }
  const std::uint64_t region_size = config->size - kKeySize;
  const std::span<const std::uint8_t> config_region =
      image.subspan(static_cast<std::size_t>(config->file_offset), static_cast<std::size_t>(region_size));
  const std::span<const std::uint8_t> share_lib =
      image.subspan(static_cast<std::size_t>(config->file_offset + region_size), kKeySize);

  const std::optional<checks::TextRegion> text = checks::find_text_region(image, 0);
  if (!text.has_value()) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> text_bytes =
      image.subspan(static_cast<std::size_t>(text->file_offset), static_cast<std::size_t>(text->size));

  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> config_digest = checks::sha256(config_region);
  const std::optional<std::array<std::uint8_t, checks::kDigestSize>> text_digest = checks::sha256(text_bytes);
  if (!config_digest.has_value() || !text_digest.has_value()) {
    return std::nullopt;
  }

  const std::optional<std::vector<std::uint8_t>> share_asset = apk::read_stored_entry(apk, kShareEntry);
  if (!share_asset.has_value() || share_asset->size() != kKeySize) {
    return std::nullopt;
  }

  return root_key(share_lib, *share_asset, *config_digest, *text_digest, gate_block(environment));
}

}  // namespace rasp::android::payload
