/// DNS frame encoder: builds report payloads and splits them into DNS query names.

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rasp::reporting {

/// The number of payload bytes one DNS name can carry.
inline constexpr std::uint32_t kChunkBytes = 118;

/// The maximum number of chunks (DNS names) per report.
inline constexpr std::uint32_t kMaxChunks = 255;

/// The maximum length of one DNS label.
inline constexpr std::uint32_t kMaxLabelLength = 63;

/// The maximum number of data labels per DNS name.
inline constexpr std::uint32_t kMaxDataLabels = 3;

/// The maximum number of bytes the zone may occupy (including length bytes for each label).
inline constexpr std::uint32_t kMaxZoneBytes = 48;

/// Unix timestamp of 2026-01-01 00:00 UTC, the epoch of the hour field.
inline constexpr std::int64_t kEpochSeconds = 1767225600;

/// The format byte for an unencrypted payload.
inline constexpr std::uint8_t kFormatPlain = 1;

/// The version of the payload format.
inline constexpr std::uint8_t kPayloadVersion = 1;

/// The number of bytes in a build reference.
inline constexpr std::uint32_t kBuildRefBytes = 16;

/// The number of bytes in an installation id.
inline constexpr std::uint32_t kInstallIdBytes = 16;

/// The number of bytes in a message id.
inline constexpr std::uint32_t kMsgIdBytes = 4;

/// Gives the hour field for a Unix timestamp.
///
/// @param unix_seconds Seconds since 1970-01-01 00:00 UTC.
/// @return Hours since 2026-01-01 00:00 UTC, clamped to [0, 65535].
[[nodiscard]] constexpr std::uint16_t hour_of(std::int64_t unix_seconds) {
  if (unix_seconds < kEpochSeconds) {
    return 0;
  }
  const std::int64_t hours = (unix_seconds - kEpochSeconds) / 3600;
  if (hours > 65535) {
    return 65535;
  }
  return static_cast<std::uint16_t>(hours);
}

/// Builds the payload of a DNS report: version + build_ref + hour + install_id + observations + CRC-32.
///
/// @param build_ref The first 16 bytes of the build id hash.
/// @param hour Hours since 2026-01-01 00:00 UTC.
/// @param install_id The 16-byte installation id.
/// @param observations The CBOR-encoded observations.
/// @param msg_id The 4-byte message id.
/// @return The payload bytes.
[[nodiscard]] std::vector<std::uint8_t> write_payload(std::span<const std::uint8_t, kBuildRefBytes> build_ref,
                                                      std::uint16_t hour,
                                                      std::span<const std::uint8_t, kInstallIdBytes> install_id,
                                                      const std::vector<std::uint8_t>& observations,
                                                      std::span<const std::uint8_t, kMsgIdBytes> msg_id);

/// Splits a payload into DNS query names for a given zone.
///
/// Each name is `<data-labels>.<routing-label>.<zone>`, where the data labels hold one
/// chunk of the payload and the routing label ties the chunks together.
///
/// @param payload The payload (from write_payload).
/// @param msg_id The 4-byte message id.
/// @param zone The DNS zone suffix (e.g. "rsp.example.com").
/// @return The DNS names, one per chunk. Empty if the payload is too large or the zone is invalid.
[[nodiscard]] std::vector<std::string> write_names(const std::vector<std::uint8_t>& payload,
                                                   std::span<const std::uint8_t, kMsgIdBytes> msg_id,
                                                   const std::string& zone);

}  // namespace rasp::reporting
