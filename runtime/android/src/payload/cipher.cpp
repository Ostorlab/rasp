/// decrypt, which hands the payload frame to TF-PSA-Crypto's ChaCha20-Poly1305, through the PSA API.

#include "payload/cipher.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <vector>

namespace rasp::android::payload {

namespace {

/// The size of the nonce at the start of a frame, in bytes, as RFC 8439 fixes it.
constexpr std::size_t kNonceSize = 12;

/// The size of the Poly1305 tag at the end of a frame, in bytes.
constexpr std::size_t kTagSize = 16;

/// Imports `key` into PSA as a ChaCha20-Poly1305 decryption key, or gives nothing when PSA refuses it.
[[nodiscard]] std::optional<psa_key_id_t> import_key(std::span<const std::uint8_t> key) {
  psa_key_attributes_t attributes = psa_key_attributes_init();
  psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
  psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(kKeySize));
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  if (psa_import_key(&attributes, key.data(), key.size(), &key_id) != PSA_SUCCESS) {
    return std::nullopt;
  }
  return key_id;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> decrypt(std::span<const std::uint8_t> key,
                                                 std::span<const std::uint8_t> frame) {
  if (key.size() != kKeySize || frame.size() < kNonceSize + kTagSize) {
    return std::nullopt;
  }
  if (psa_crypto_init() != PSA_SUCCESS) {
    return std::nullopt;
  }
  const std::optional<psa_key_id_t> key_id = import_key(key);
  if (!key_id) {
    return std::nullopt;
  }

  const std::span<const std::uint8_t> nonce = frame.first(kNonceSize);
  const std::span<const std::uint8_t> sealed = frame.subspan(kNonceSize);
  std::vector<std::uint8_t> plaintext(sealed.size() - kTagSize);
  std::size_t written = 0;
  const psa_status_t status =
      psa_aead_decrypt(*key_id, PSA_ALG_CHACHA20_POLY1305, nonce.data(), nonce.size(), nullptr, 0, sealed.data(),
                       sealed.size(), plaintext.data(), plaintext.size(), &written);
  psa_destroy_key(*key_id);
  if (status != PSA_SUCCESS || written != plaintext.size()) {
    return std::nullopt;
  }
  return plaintext;
}

}  // namespace rasp::android::payload
