/// Bounded configuration hashing through the same vendored PSA API used by runtime integrity checks.
#include "rasp/local_policy.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <psa/crypto.h>
#include <string>
#include <string_view>
#include <vector>

namespace rasp {
std::string local_policy_hash(std::string_view text) {
  if (text.size() > 8192 || psa_crypto_init() != PSA_SUCCESS) {
    return {};
  }
  std::array<std::uint8_t, 32> digest{};
  std::size_t length = 0;
  std::vector<std::uint8_t> bytes;
  bytes.reserve(text.size());
  for (const char character : text) {
    bytes.push_back(static_cast<std::uint8_t>(character));
  }
  if (psa_hash_compute(PSA_ALG_SHA_256, bytes.data(), bytes.size(), digest.data(), digest.size(), &length) !=
          PSA_SUCCESS ||
      length != digest.size()) {
    return {};
  }
  constexpr std::string_view kHex = "0123456789abcdef";
  std::string output;
  output.reserve(64);
  for (const auto byte : digest) {
    output += kHex[byte >> 4U];
    output += kHex[byte & 15U];
  }
  return output;
}
}  // namespace rasp
