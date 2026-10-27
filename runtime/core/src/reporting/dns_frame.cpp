/// DNS frame encoder: builds report payloads and splits them into DNS query names.

#include "rasp/reporting/dns_frame.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "rasp/reporting/base32hex.h"

namespace rasp::reporting {

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

/// Computes the CRC-32 checksum (ISO 3309) of a byte span.
///
/// @param data The bytes to checksum.
/// @return The CRC-32 value.
[[nodiscard]] std::uint32_t crc32(std::span<const std::uint8_t> data) {
  std::uint32_t crc = 0xFFFFFFFFU;
  for (const std::uint8_t byte : data) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    crc = kCrc32Table[(crc ^ byte) & 0xFFU] ^ (crc >> 8U);
  }
  return crc ^ 0xFFFFFFFFU;
}

/// Computes the CRC-32 check over [format_byte] + msg_id + payload_body.
///
/// @param format_byte The format byte (e.g. kFormatPlain).
/// @param msg_id The 4-byte message id.
/// @param payload_body The payload body (version + build_ref + hour + install_id + observations).
/// @return The CRC-32 value.
[[nodiscard]] std::uint32_t check_of(std::uint8_t format_byte, std::span<const std::uint8_t, kMsgIdBytes> msg_id,
                                     const std::vector<std::uint8_t>& payload_body) {
  std::vector<std::uint8_t> buffer;
  buffer.reserve(1 + kMsgIdBytes + payload_body.size());
  buffer.push_back(format_byte);
  buffer.insert(buffer.end(), msg_id.begin(), msg_id.end());
  buffer.insert(buffer.end(), payload_body.begin(), payload_body.end());
  return crc32(buffer);
}

/// Builds the base32hex-encoded routing label for one chunk.
///
/// The routing label is 8 raw bytes: [format, msg_id[0..3], index, count, data_len],
/// encoded as 13 base32hex characters.
///
/// @param msg_id The 4-byte message id.
/// @param index The zero-based chunk index.
/// @param count The total number of chunks.
/// @param data_len The number of payload bytes in this chunk.
/// @return The 13-character routing label.
[[nodiscard]] std::string write_routing(std::span<const std::uint8_t, kMsgIdBytes> msg_id, std::uint8_t index,
                                        std::uint8_t count, std::uint8_t data_len) {
  const std::array<std::uint8_t, kRoutingBytes> raw = {
      kFormatPlain, msg_id[0], msg_id[1], msg_id[2], msg_id[3], index, count, data_len,
  };
  return encode(raw);
}

/// Checks whether a zone string is valid for DNS query names.
///
/// A valid zone is non-empty, has no leading or trailing dots, every label is
/// between 1 and kMaxLabelLength bytes, and its wire-format size (each label
/// prefixed by a length byte) fits kMaxZoneBytes.
[[nodiscard]] bool valid_zone(const std::string& zone) {
  if (zone.empty() || zone.front() == '.' || zone.back() == '.') {
    return false;
  }
  std::uint32_t wire_bytes = 0;
  std::uint32_t label_len = 0;
  for (const char character : zone) {
    if (character == '.') {
      if (label_len == 0 || label_len > kMaxLabelLength) {
        return false;
      }
      wire_bytes += 1 + label_len;
      label_len = 0;
    } else {
      ++label_len;
    }
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
  // Build payload_body: version(1B) + build_ref(16B) + hour(2B big-endian) + install_id(16B) + observations.
  std::vector<std::uint8_t> payload_body;
  payload_body.reserve(1 + kBuildRefBytes + 2 + kInstallIdBytes + observations.size());

  payload_body.push_back(kPayloadVersion);
  payload_body.insert(payload_body.end(), build_ref.begin(), build_ref.end());
  payload_body.push_back(static_cast<std::uint8_t>(hour >> 8U));
  payload_body.push_back(static_cast<std::uint8_t>(hour & 0xFFU));
  payload_body.insert(payload_body.end(), install_id.begin(), install_id.end());
  payload_body.insert(payload_body.end(), observations.begin(), observations.end());

  // Compute CRC-32 over [FORMAT_PLAIN] + msg_id + payload_body.
  const std::uint32_t check = check_of(kFormatPlain, msg_id, payload_body);

  // Append check as 4 bytes big-endian.
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

  // Check that the payload fits within the maximum number of chunks.
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

    // Base32hex encode the chunk.
    const std::string encoded = encode(std::span<const std::uint8_t>(payload).subspan(offset, chunk_size));

    // Split the encoded string into labels of at most kMaxLabelLength characters.
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

    // Append the routing label and the zone.
    name += '.';
    name += write_routing(msg_id, static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(chunk_count),
                          static_cast<std::uint8_t>(chunk_size));
    name += '.';
    name += zone;

    names.push_back(name);
  }

  return names;
}

}  // namespace rasp::reporting
