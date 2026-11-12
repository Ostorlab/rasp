/// Bounded DER envelope checks and digest-only normalization shared by APK and public PackageManager sources.

#include "util/signing_certificates.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "checks/integrity.h"

namespace rasp::android::util {
namespace {

/// Consumes one DER field with a known single-byte tag and canonical definite length.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> der_field(std::span<const std::uint8_t>& bytes,
                                                                     std::uint8_t tag) {
  if (bytes.size() < 2 || bytes[0] != tag) {
    return std::nullopt;
  }
  std::size_t length = bytes[1];
  std::size_t header = 2;
  if (length >= 128) {
    const std::size_t count = length & 0x7fU;
    if (count == 0 || count > 3 || bytes.size() < header + count || bytes[header] == 0) {
      return std::nullopt;
    }
    length = 0;
    for (std::size_t index = 0; index < count; ++index) {
      length = (length << 8U) | bytes[header + index];
    }
    header += count;
    if (length < 128) {
      return std::nullopt;
    }
  }
  if (length == 0 || length > bytes.size() - header) {
    return std::nullopt;
  }
  const auto field = bytes.subspan(header, length);
  bytes = bytes.subspan(header + length);
  return field;
}

}  // namespace

bool certificate_envelope(std::span<const std::uint8_t> certificate) {
  if (certificate.size() > kMaxCertificateBytes) {
    return false;
  }
  auto sequence = der_field(certificate, 0x30);
  if (!sequence.has_value() || !certificate.empty()) {
    return false;
  }
  const auto tbs = der_field(*sequence, 0x30);
  const auto algorithm = der_field(*sequence, 0x30);
  const auto signature = der_field(*sequence, 0x03);
  return tbs.has_value() && algorithm.has_value() && signature.has_value() && sequence->empty() &&
         signature->size() > 1 && (*signature)[0] == 0;
}

std::optional<std::vector<std::string>> certificate_digests(const std::optional<Certificates>& certificates,
                                                            bool history) {
  if (!certificates.has_value() || certificates->empty() || certificates->size() > kMaxCertificates) {
    return std::nullopt;
  }
  std::vector<std::string> digests;
  std::size_t total = 0;
  for (const auto& certificate : *certificates) {
    if (certificate.size() > kMaxCertificateTotalBytes - total || !certificate_envelope(certificate)) {
      return std::nullopt;
    }
    total += certificate.size();
    const auto digest = checks::sha256_hex(certificate);
    if (!digest.has_value()) {
      return std::nullopt;
    }
    digests.push_back(*digest);
  }
  if (!history) {
    std::ranges::sort(digests);
    digests.erase(std::ranges::unique(digests).begin(), digests.end());
  }
  return digests;
}

}  // namespace rasp::android::util
