/// DNS report builder: encodes observations as DNS query names for the collector.

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "rasp/observation.h"
#include "rasp/reporting/dns_frame.h"

namespace rasp::reporting {

/// The inputs that identify the app installation and tell the report where to go.
struct ReportContext {
  /// The first 16 bytes of the build id hash.
  std::array<std::uint8_t, kBuildRefBytes> build_ref{};
  /// The 16-byte installation id (UUID bytes).
  std::array<std::uint8_t, kInstallIdBytes> install_id{};
  /// The DNS zone that the collector listens on (e.g. "rsp.example.com").
  std::string zone;
};

/// Encodes observations as DNS A-record query names.
///
/// Generates a random 4-byte message id, CBOR-encodes the observations, builds the
/// payload with the report header and CRC-32, chunks it, and returns one DNS name
/// per chunk, ready to be resolved with getaddrinfo or equivalent.
///
/// @param observations The security observations to report.
/// @param context The build, install and zone information.
/// @return The DNS query names, one per chunk. Empty if encoding fails.
[[nodiscard]] std::vector<std::string> build_report(const std::vector<Observation>& observations,
                                                    const ReportContext& context);

}  // namespace rasp::reporting
