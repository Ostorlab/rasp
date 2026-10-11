/// decrypt, which checks a frame's HMAC-SHA256 tag and then XORs its body with an HMAC-SHA256 counter keystream.

#include "payload/cipher.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <string_view>
#include <vector>

#include "rasp/util/sha256.h"

namespace rasp::android::payload {

namespace {

/// The bytes every frame starts with, `RASP` in ASCII.
constexpr std::array<std::uint8_t, 4> kMagic = {0x52, 0x41, 0x53, 0x50};

/// The only frame version this code reads.
constexpr std::uint8_t kFrameVersion = 1;

/// The size of the nonce, in bytes.
constexpr std::size_t kNonceSize = 16;

/// The size of the tag at the end of a frame, in bytes.
constexpr std::size_t kTagSize = 32;

/// The size of the header: the magic bytes, the version byte and the nonce.
constexpr std::size_t kHeaderSize = kMagic.size() + 1 + kNonceSize;

/// The size of the block counter after the nonce in a keystream input, in bytes.
constexpr std::size_t kCounterSize = 8;

/// The label of the subkey that makes the keystream.
constexpr std::string_view kEncryptLabel = "rasp/android/encrypt/v1";

/// The label of the subkey that makes the tag.
constexpr std::string_view kAuthenticateLabel = "rasp/android/authenticate/v1";

/// Derives the subkey for `label` from `key`.
[[nodiscard]] Sha256Digest subkey(std::span<const std::uint8_t> key, std::string_view label) {
  const std::vector<std::uint8_t> label_bytes(label.begin(), label.end());
  return hmac_sha256(key, label_bytes);
}

/// Whether `left` and `right` hold the same bytes, in a time that doesn't depend on where they differ.
[[nodiscard]] bool equal_constant_time(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) {
  if (left.size() != right.size()) {
    return false;
  }
  std::uint32_t difference = 0;
  for (const auto [left_byte, right_byte] : std::views::zip(left, right)) {
    difference |= static_cast<std::uint32_t>(left_byte) ^ static_cast<std::uint32_t>(right_byte);
  }
  return difference == 0;
}

/// Writes `counter` into `bytes` in big-endian order, the most significant byte first.
void store_counter(std::uint64_t counter, std::span<std::uint8_t, kCounterSize> bytes) {
  for (std::uint8_t& byte : std::views::reverse(bytes)) {
    byte = static_cast<std::uint8_t>(counter);
    counter >>= 8U;
  }
}

}  // namespace

std::optional<std::vector<std::uint8_t>> decrypt(std::span<const std::uint8_t> key,
                                                 std::span<const std::uint8_t> frame) {
  if (key.size() != kKeySize) {
    return std::nullopt;
  }
  if (frame.size() < kHeaderSize + kTagSize) {
    return std::nullopt;
  }
  if (!std::ranges::equal(frame.first(kMagic.size()), kMagic)) {
    return std::nullopt;
  }
  if (frame[kMagic.size()] != kFrameVersion) {
    return std::nullopt;
  }

  const std::span<const std::uint8_t> header = frame.first(kHeaderSize);
  const std::span<const std::uint8_t> body = frame.subspan(kHeaderSize, frame.size() - kHeaderSize - kTagSize);
  const std::span<const std::uint8_t> tag = frame.last(kTagSize);
  const std::span<const std::uint8_t> nonce = frame.subspan(kMagic.size() + 1, kNonceSize);

  const Sha256Digest authenticate_key = subkey(key, kAuthenticateLabel);
  std::vector<std::uint8_t> authenticated;
  authenticated.reserve(header.size() + body.size());
  authenticated.insert(authenticated.end(), header.begin(), header.end());
  authenticated.insert(authenticated.end(), body.begin(), body.end());
  const Sha256Digest expected = hmac_sha256(authenticate_key, authenticated);
  if (!equal_constant_time(tag, expected)) {
    return std::nullopt;
  }

  const Sha256Digest encrypt_key = subkey(key, kEncryptLabel);
  std::vector<std::uint8_t> plaintext(body.begin(), body.end());
  std::array<std::uint8_t, kNonceSize + kCounterSize> counter_input{};
  std::ranges::copy(nonce, counter_input.begin());
  const std::span<std::uint8_t, kCounterSize> counter_bytes = std::span(counter_input).last<kCounterSize>();
  std::uint64_t counter = 0;
  std::span<std::uint8_t> rest(plaintext);
  while (!rest.empty()) {
    store_counter(counter, counter_bytes);
    const Sha256Digest keystream = hmac_sha256(encrypt_key, counter_input);
    for (auto [byte, keystream_byte] : std::views::zip(rest, keystream)) {
      byte = static_cast<std::uint8_t>(byte ^ keystream_byte);
    }
    rest = rest.subspan(std::min(keystream.size(), rest.size()));
    ++counter;
  }
  return plaintext;
}

}  // namespace rasp::android::payload
