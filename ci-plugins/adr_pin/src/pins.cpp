/// observe and pin_of: hash the public key of each certificate of a handshake's chain, and report the keys and the
/// system's trust.

#include "pins.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base64.h"
#include "der.h"
#include "handshake.h"
#include "rasp/observation.h"

namespace rasp::plugins::adr_pin {

namespace {

/// An observation of a check that did not finish in time, with no value.
///
/// @param signal What the check tried to observe.
/// @param source How the check tried to read it.
/// @return The observation, with status `kTimeout` and an empty value.
[[nodiscard]] Observation timed_out(std::string_view signal, std::string_view source) {
  return Observation{
      .signal = std::string(signal),
      .source = std::string(source),
      .status = Status::kTimeout,
      .value = {},
  };
}

/// The pin observation of a chain that was read.
///
/// @param chain The chain, leaf first.
/// @param hash The SHA-256.
/// @return The pins, or an error when one can't be computed or the chain is empty.
[[nodiscard]] Observation observe_chain(const std::vector<std::vector<std::uint8_t>>& chain, Hash hash) {
  if (chain.empty()) {
    return failed(kPinSignal, kPinSource);
  }
  const std::size_t count = std::min(chain.size(), kMaxCertificates);
  std::vector<std::string> pins;
  pins.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    std::optional<std::string> pin = pin_of(chain[index], hash);
    if (!pin.has_value()) {
      return failed(kPinSignal, kPinSource);
    }
    pins.push_back(*std::move(pin));
  }
  return observed(kPinSignal, kPinSource, std::move(pins));
}

}  // namespace

std::optional<std::string> pin_of(std::span<const std::uint8_t> certificate, Hash hash) {
  const std::optional<std::span<const std::uint8_t>> spki = spki_of(certificate);
  if (!spki.has_value()) {
    return std::nullopt;
  }
  const std::optional<Digest> digest = hash(*spki);
  if (!digest.has_value()) {
    return std::nullopt;
  }
  return std::string(kPinPrefix) + base64(*digest);
}

std::vector<Observation> observe(const Handshake& handshake, Hash hash) {
  switch (handshake.outcome) {
    case Outcome::kRead:
      return {observe_chain(handshake.chain, hash), observed(kTrustedSignal, kTrustedSource, handshake.trusted)};
    case Outcome::kTimeout:
      return {timed_out(kPinSignal, kPinSource), timed_out(kTrustedSignal, kTrustedSource)};
    case Outcome::kFailed:
      return {failed(kPinSignal, kPinSource), failed(kTrustedSignal, kTrustedSource)};
    case Outcome::kUnsupported:
      break;
  }
  return {unsupported(kPinSignal, kPinSource), unsupported(kTrustedSignal, kTrustedSource)};
}

}  // namespace rasp::plugins::adr_pin
