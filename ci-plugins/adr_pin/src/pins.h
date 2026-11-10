/// observe and pin_of: turn a handshake into the pin probe's observations.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "handshake.h"
#include "rasp/observation.h"

namespace rasp::plugins::adr_pin {

/// The signal of the keys the host presented.
constexpr std::string_view kPinSignal = "mitm.adr_pin";
/// The source of the keys: the TLS handshake, made through Network.framework.
constexpr std::string_view kPinSource = "network_framework";
/// The signal of whether the system trusted the chain.
constexpr std::string_view kTrustedSignal = "mitm.adr_trusted";
/// The source of the trust: the system's own evaluation of the chain.
constexpr std::string_view kTrustedSource = "sec_trust";

/// The text before the base64 digest of a pin.
constexpr std::string_view kPinPrefix = "sha256/";

/// A function that hashes bytes with SHA-256.
using Hash = std::optional<Digest> (*)(std::span<const std::uint8_t> bytes);

/// The SPKI pin of a certificate: `sha256/` and the base64 SHA-256 of its SubjectPublicKeyInfo, the format of
/// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.
///
/// @param certificate The certificate's DER.
/// @param hash The SHA-256.
/// @return The pin, or nothing when the DER is not a certificate or the hash failed.
[[nodiscard]] std::optional<std::string> pin_of(std::span<const std::uint8_t> certificate, Hash hash);

/// The two observations of a handshake.
///
/// - `mitm.adr_pin` through `network_framework`: the pin of each certificate of the chain, leaf first, at most
///   kMaxCertificates. An error when a certificate's pin can't be computed: a pin is never left out silently.
/// - `mitm.adr_trusted` through `sec_trust`: whether the system trusted the chain.
///
/// A handshake that timed out gives two timeouts, one that failed gives two errors, and one that can't run here gives
/// two unsupported observations. The server decides what the keys mean: the runtime only reports them.
///
/// @param handshake The handshake.
/// @param hash The SHA-256.
/// @return The two observations, `mitm.adr_pin` first.
[[nodiscard]] std::vector<Observation> observe(const Handshake& handshake, Hash hash);

}  // namespace rasp::plugins::adr_pin
