/// handshake and sha256: the platform's part of the pin probe. The TLS handshake that reads the certificate chain a
/// host presents, and the SHA-256 that hashes a key.

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rasp::plugins::adr_pin {

/// The most certificates of a chain the probe keeps, so a forged chain can't grow the pin observation without bound.
/// A real chain has two to four.
constexpr std::size_t kMaxCertificates = 10;

/// The most bytes of one certificate the probe keeps. A real certificate is a few kilobytes; a larger one is kept
/// empty, so its pin is reported as an error.
constexpr std::size_t kMaxCertificateBytes = std::size_t{64} * 1024;

/// How a handshake ended.
enum class Outcome : std::uint8_t {
  /// The host presented a certificate chain, which was read. The handshake was then stopped.
  kRead,
  /// No certificate chain arrived before the timeout, for example without a network: the connection waits for a path
  /// until then.
  kTimeout,
  /// The connection failed for good before any certificate arrived.
  kFailed,
  /// The probe cannot run here, for example on a simulator.
  kUnsupported,
};

/// The result of a handshake.
struct Handshake {
  /// How the handshake ended.
  Outcome outcome = Outcome::kUnsupported;
  /// The DER of each certificate the host presented, leaf first, at most kMaxCertificates. Only set with kRead.
  std::vector<std::vector<std::uint8_t>> chain;
  /// Whether the system trusted the chain for the host, with the trust store the app's own connections use. Only set
  /// with kRead.
  bool trusted = false;
};

/// A SHA-256 digest.
using Digest = std::array<std::uint8_t, 32>;

/// Opens a TLS connection to port 443 of `host`, reads the certificate chain the host presents and how the system
/// judges it, then stops the handshake. No request is sent. The connection goes the way the app's own connections go,
/// through the system's proxy and VPN.
///
/// @param host The host name, such as `rasp.example.com`.
/// @param timeout How long to wait for the chain.
/// @return How the handshake ended, with the chain when it was read.
[[nodiscard]] Handshake handshake(const std::string& host, std::chrono::milliseconds timeout);

/// The SHA-256 of `bytes`.
///
/// @param bytes The bytes to hash.
/// @return The digest, or nothing when the platform has no SHA-256 here.
[[nodiscard]] std::optional<Digest> sha256(std::span<const std::uint8_t> bytes);

}  // namespace rasp::plugins::adr_pin
