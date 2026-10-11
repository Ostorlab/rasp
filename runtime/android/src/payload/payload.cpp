/// unpack, which decrypts the payload and reads the dex files from its decrypted bytes with bounds checks.

#include "payload/payload.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "payload/cipher.h"

namespace rasp::android::payload {

namespace {

/// The size of a big-endian 32-bit number, in bytes.
constexpr std::size_t kNumberSize = 4;

/// The fewest bytes a dex file takes in the decrypted payload: its two lengths.
constexpr std::size_t kSmallestEntrySize = 2 * kNumberSize;

/// Reads the first `size` bytes of `rest` and moves `rest` past them, or gives nothing when `rest` is shorter.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> read_bytes(std::span<const std::uint8_t>& rest,
                                                                      std::size_t size) {
  if (size > rest.size()) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> bytes = rest.first(size);
  rest = rest.subspan(size);
  return bytes;
}

/// Reads a big-endian 32-bit number at the start of `rest` and moves past it, or gives nothing when it's too short.
[[nodiscard]] std::optional<std::uint32_t> read_number(std::span<const std::uint8_t>& rest) {
  const std::optional<std::span<const std::uint8_t>> bytes = read_bytes(rest, kNumberSize);
  if (!bytes) {
    return std::nullopt;
  }
  std::uint32_t number = 0;
  for (const std::uint8_t byte : *bytes) {
    number = (number << 8U) | static_cast<std::uint32_t>(byte);
  }
  return number;
}

/// Reads a length and then that many bytes from `rest`, or gives nothing when either goes past its end.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> read_field(std::span<const std::uint8_t>& rest) {
  const std::optional<std::uint32_t> length = read_number(rest);
  if (!length) {
    return std::nullopt;
  }
  return read_bytes(rest, *length);
}

}  // namespace

std::optional<std::vector<Dex>> unpack(std::span<const std::uint8_t> key, std::span<const std::uint8_t> frame) {
  const std::optional<std::vector<std::uint8_t>> plaintext = decrypt(key, frame);
  if (!plaintext) {
    return std::nullopt;
  }
  std::span<const std::uint8_t> rest(*plaintext);

  const std::optional<std::uint32_t> count = read_number(rest);
  if (!count || *count > rest.size() / kSmallestEntrySize) {
    return std::nullopt;
  }

  std::vector<Dex> dexes;
  dexes.reserve(*count);
  for (std::uint32_t index = 0; index < *count; ++index) {
    const std::optional<std::span<const std::uint8_t>> name = read_field(rest);
    if (!name) {
      return std::nullopt;
    }
    const std::optional<std::span<const std::uint8_t>> data = read_field(rest);
    if (!data) {
      return std::nullopt;
    }
    dexes.push_back(Dex{.name = {name->begin(), name->end()}, .data = {data->begin(), data->end()}});
  }
  return dexes;
}

}  // namespace rasp::android::payload
