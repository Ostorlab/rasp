/// sha256_hex: the SHA-256 of the iOS checks, through TF-PSA-Crypto's PSA Crypto API.

#include "util/sha256.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <psa/crypto.h>
#include <span>
#include <string>
#include <string_view>

namespace rasp::ios::util {

namespace {

/// The length of a SHA-256 digest, in bytes.
constexpr std::size_t kDigestSize = 32;

}  // namespace

std::optional<std::string> sha256_hex(std::span<const std::uint8_t> bytes) {
  if (psa_crypto_init() != PSA_SUCCESS) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kDigestSize> digest{};
  std::size_t length = 0;
  const psa_status_t status =
      psa_hash_compute(PSA_ALG_SHA_256, bytes.data(), bytes.size(), digest.data(), digest.size(), &length);
  if (status != PSA_SUCCESS || length != digest.size()) {
    return std::nullopt;
  }
  constexpr std::string_view kDigits = "0123456789abcdef";
  std::string hex;
  hex.reserve(digest.size() * 2);
  for (const std::uint8_t byte : digest) {
    hex.push_back(kDigits[byte >> 4U]);
    hex.push_back(kDigits[byte & 0x0FU]);
  }
  return hex;
}

}  // namespace rasp::ios::util
