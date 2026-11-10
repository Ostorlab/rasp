/// spki_of: finds the public key of an X.509 certificate in its DER.

#pragma once

#include <cstdint>
#include <optional>
#include <span>

namespace rasp::plugins::adr_pin {

/// The SubjectPublicKeyInfo of an X.509 certificate (RFC 5280 section 4.1): the public key and its algorithm, as the
/// whole DER element, tag and length included. It is what an SPKI pin hashes.
///
/// The walk is bounded: it never reads past `certificate`, and it refuses an indefinite length, a length of more than
/// four bytes, a multi-byte tag, a missing field and any byte after the certificate.
///
/// @param certificate The certificate's DER.
/// @return The SubjectPublicKeyInfo element, a part of `certificate`, or nothing when the DER is not a certificate.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> spki_of(std::span<const std::uint8_t> certificate);

}  // namespace rasp::plugins::adr_pin
