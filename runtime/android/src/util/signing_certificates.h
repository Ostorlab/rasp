/// Bounds and digest conversion for untrusted signer certificate observations, without signature verification.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rasp::android::util {

/// Raw certificate bytes, retained only within a collection pass and never emitted as telemetry.
using Certificates = std::vector<std::vector<std::uint8_t>>;
/// Maximum raw certificate count before normalization, including rotation history.
inline constexpr std::size_t kMaxCertificates = 32;
/// Maximum bytes in one DER certificate.
inline constexpr std::size_t kMaxCertificateBytes = 65536;
/// Maximum certificate bytes across a collection, before normalization.
inline constexpr std::size_t kMaxCertificateTotalBytes = 262144;

/// Checks canonical DER lengths and the three-field X.509 envelope, without validating the certificate or its key.
/// @param certificate Untrusted encoded certificate.
/// @return Whether the bounded envelope is well formed; no trust or signature claim follows from this check.
[[nodiscard]] bool certificate_envelope(std::span<const std::uint8_t> certificate);

/// Hashes a nonempty bounded collection; current sets are sorted and deduplicated, history retains input order.
/// @param certificates Raw certificate buffers, or unavailable.
/// @param history Whether the input is ordered rotation history rather than concurrent signers.
/// @return Lowercase SHA256 hex digests, or nothing on malformed/empty/over-limit input or hashing failure.
[[nodiscard]] std::optional<std::vector<std::string>> certificate_digests(
    const std::optional<Certificates>& certificates, bool history = false);

}  // namespace rasp::android::util
