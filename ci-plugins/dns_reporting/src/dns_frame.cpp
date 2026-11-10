/// DNS frame encoder: builds report payloads and splits them into DNS query names.

#include "dns_frame.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "base32hex.h"

namespace rasp::plugins::dns_reporting {

namespace {

/// The number of raw bytes in a routing label before base32hex encoding.
constexpr std::uint32_t kRoutingBytes = 8;

/// Standard CRC-32 lookup table with the reflected polynomial 0xEDB88320.
constexpr std::array<std::uint32_t, 256> kCrc32Table = [] {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t crc = i;
    for (int j = 0; j < 8; ++j) {
      if ((crc & 1U) != 0U) {
        crc = (crc >> 1U) ^ 0xEDB88320U;
      } else {
        crc >>= 1U;
      }
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    table[i] = crc;
  }
  return table;
}();

/// Updates a running CRC-32 (ISO 3309) with a span of bytes.
[[nodiscard]] std::uint32_t crc32_update(std::uint32_t crc, std::span<const std::uint8_t> data) {
  for (const std::uint8_t byte : data) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    crc = kCrc32Table[(crc ^ byte) & 0xFFU] ^ (crc >> 8U);
  }
  return crc;
}

/// Finalises a running CRC-32 value.
[[nodiscard]] std::uint32_t crc32_final(std::uint32_t crc) { return crc ^ 0xFFFFFFFFU; }

/// Computes the CRC-32 check over [format_byte] + msg_id + payload_body without copying.
[[nodiscard]] std::uint32_t check_of(std::uint8_t format_byte, std::span<const std::uint8_t, kMsgIdBytes> msg_id,
                                     const std::vector<std::uint8_t>& payload_body) {
  std::uint32_t crc = 0xFFFFFFFFU;
  crc = crc32_update(crc, std::span<const std::uint8_t>(&format_byte, 1));
  crc = crc32_update(crc, msg_id);
  crc = crc32_update(crc, payload_body);
  return crc32_final(crc);
}

/// Builds the base32hex-encoded routing label for one chunk.
[[nodiscard]] std::string write_routing(std::span<const std::uint8_t, kMsgIdBytes> msg_id, std::uint8_t index,
                                        std::uint8_t count, std::uint8_t data_len) {
  const std::array<std::uint8_t, kRoutingBytes> raw = {
      kFormatPlain, msg_id[0], msg_id[1], msg_id[2], msg_id[3], index, count, data_len,
  };
  return encode(raw);
}

/// Whether a character is a valid DNS hostname character (letter, digit or hyphen).
[[nodiscard]] constexpr bool is_hostname_char(char character) {
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
         (character >= '0' && character <= '9') || character == '-';
}

/// Checks whether a zone string is valid for DNS query names.
///
/// Each label must contain only letters, digits and hyphens, must not start or end with a hyphen,
/// and must be between 1 and kMaxLabelLength bytes. The zone's wire-format size must fit kMaxZoneBytes.
[[nodiscard]] bool valid_zone(const std::string& zone) {
  if (zone.empty() || zone.front() == '.' || zone.back() == '.' || zone.front() == '-' || zone.back() == '-') {
    return false;
  }
  std::uint32_t wire_bytes = 0;
  std::uint32_t label_len = 0;
  char previous = '.';
  for (const char character : zone) {
    if (character == '.') {
      if (label_len == 0 || label_len > kMaxLabelLength || previous == '-') {
        return false;
      }
      wire_bytes += 1 + label_len;
      if (wire_bytes > kMaxZoneBytes) {
        return false;
      }
      label_len = 0;
    } else if (!is_hostname_char(character)) {
      return false;
    } else {
      if (character == '-' && previous == '.') {
        return false;
      }
      ++label_len;
    }
    previous = character;
  }
  if (label_len == 0 || label_len > kMaxLabelLength) {
    return false;
  }
  wire_bytes += 1 + label_len;
  return wire_bytes <= kMaxZoneBytes;
}

}  // namespace

std::vector<std::uint8_t> write_payload(std::span<const std::uint8_t, kBuildRefBytes> build_ref, std::uint16_t hour,
                                        std::span<const std::uint8_t, kInstallIdBytes> install_id,
                                        const std::vector<std::uint8_t>& observations,
                                        std::span<const std::uint8_t, kMsgIdBytes> msg_id) {
  std::vector<std::uint8_t> payload_body;
  payload_body.reserve(1 + kBuildRefBytes + 2 + kInstallIdBytes + observations.size() + 4);

  payload_body.push_back(kPayloadVersion);
  payload_body.insert(payload_body.end(), build_ref.begin(), build_ref.end());
  payload_body.push_back(static_cast<std::uint8_t>(hour >> 8U));
  payload_body.push_back(static_cast<std::uint8_t>(hour & 0xFFU));
  payload_body.insert(payload_body.end(), install_id.begin(), install_id.end());
  payload_body.insert(payload_body.end(), observations.begin(), observations.end());

  const std::uint32_t check = check_of(kFormatPlain, msg_id, payload_body);

  payload_body.push_back(static_cast<std::uint8_t>(check >> 24U));
  payload_body.push_back(static_cast<std::uint8_t>(check >> 16U));
  payload_body.push_back(static_cast<std::uint8_t>(check >> 8U));
  payload_body.push_back(static_cast<std::uint8_t>(check));

  return payload_body;
}

std::vector<std::string> write_names(const std::vector<std::uint8_t>& payload,
                                     std::span<const std::uint8_t, kMsgIdBytes> msg_id, const std::string& zone) {
  if (payload.empty() || !valid_zone(zone)) {
    return {};
  }

  const std::size_t chunk_count = (payload.size() + kChunkBytes - 1) / kChunkBytes;
  if (chunk_count > kMaxChunks) {
    return {};
  }

  std::vector<std::string> names;
  names.reserve(chunk_count);

  for (std::size_t i = 0; i < chunk_count; ++i) {
    const std::size_t offset = i * kChunkBytes;
    const std::size_t remaining = payload.size() - offset;
    const std::size_t chunk_size = remaining < kChunkBytes ? remaining : kChunkBytes;

    const std::string encoded = encode(std::span<const std::uint8_t>(payload).subspan(offset, chunk_size));

    std::string name;
    std::size_t pos = 0;
    std::uint32_t data_label_count = 0;
    while (pos < encoded.size()) {
      const std::size_t label_len = (encoded.size() - pos) < kMaxLabelLength ? (encoded.size() - pos) : kMaxLabelLength;
      if (pos > 0) {
        name += '.';
      }
      name.append(encoded, pos, label_len);
      pos += label_len;
      ++data_label_count;
    }
    if (data_label_count > kMaxDataLabels) {
      return {};
    }

    name += '.';
    name += write_routing(msg_id, static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(chunk_count),
                          static_cast<std::uint8_t>(chunk_size));
    name += '.';
    name += zone;

    names.push_back(name);
  }

  return names;
}

}  // namespace rasp::plugins::dns_reporting
