/// sha256: the SHA-256 of CommonCrypto on Apple platforms, and none elsewhere.

#include <cstdint>
#include <optional>
#include <span>

#include "handshake.h"

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <limits>
#include <tuple>
#endif

namespace rasp::plugins::adr_pin {

std::optional<Digest> sha256(std::span<const std::uint8_t> bytes) {
#ifdef __APPLE__
  static_assert(CC_SHA256_DIGEST_LENGTH == std::tuple_size_v<Digest>);
  if (bytes.size() > std::numeric_limits<CC_LONG>::max()) {
    return std::nullopt;
  }
  Digest digest{};
  static_cast<void>(CC_SHA256(bytes.data(), static_cast<CC_LONG>(bytes.size()), digest.data()));
  return digest;
#else
  static_cast<void>(bytes);
  return std::nullopt;
#endif
}

}  // namespace rasp::plugins::adr_pin
