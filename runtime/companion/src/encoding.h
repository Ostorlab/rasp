/// Bounded canonical encodings and validation shared by the owned companion service.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "rasp/local_policy_host.h"
#include "rasp/scoped_key.h"

namespace rasp::keys {
/// Owned platform-returned application identity, never a caller-selected package.
struct Application {
  std::array<std::uint8_t, 256> name{};
  std::uint32_t length = 0;
};
/// Hash bounded bytes with the existing PSA SHA256 implementation.
[[nodiscard]] bool digest(std::span<const std::uint8_t> input, std::span<std::uint8_t, 32> output);
/// Clear mutable owned data without an elidable ordinary memset.
void wipe(std::span<std::uint8_t> memory);
/// Validate explicit text length, zero tails and the closed identifier alphabet.
[[nodiscard]] bool text(std::span<const std::uint8_t> bytes, std::uint32_t length, bool audience = false);
/// Check every config field and tail before admission.
[[nodiscard]] bool valid_spec(const RaspScopedKeyClientSpecV1& input);
/// Check the closed operation union, strings, TTL and all unused bytes.
[[nodiscard]] bool valid_submit(const RaspScopedKeySubmitV1& input);
/// Validate canonical UTF8 without controls or NUL; no normalization.
[[nodiscard]] bool utf8(std::span<const std::uint8_t> bytes);
/// Produce exact profile bytes, returning zero on exhausted output or invalid identity.
[[nodiscard]] std::size_t profile_bytes(const Application& app, const RaspScopedKeyClientSpecV1& client,
                                        const RaspScopedKeyNamespaceSpecV1& space, std::span<std::uint8_t> output);
/// Produce the internally domain-bound full message; never accepts a raw caller digest.
[[nodiscard]] std::size_t message_bytes(const Application& app, const RaspScopedKeyClientSpecV1& client,
                                        const RaspScopedKeyNamespaceSpecV1& space, const RaspScopedKeyInfoV1& key,
                                        const RaspScopedKeySignInputV1& input, std::span<std::uint8_t> output);
/// Validate canonical uncompressed P-256 public coordinates and curve membership without heap state.
[[nodiscard]] bool valid_point(std::span<const std::uint8_t, 65> point);
/// Apply only the actual shipping gate status/action and explicit namespace advisory profile.
[[nodiscard]] bool gate_allowed(std::int32_t status, const RaspLocalGateResultV1& gate, std::uint32_t mode);
/// Validate measured properties and the exact immutable requested key profile.
/// Persistent reservation metadata must match its exact namespace even before a public key exists.
[[nodiscard]] bool valid_binding(const RaspScopedKeyInfoV1& info, const RaspScopedKeyNamespaceSpecV1& space);
[[nodiscard]] bool valid_info(const RaspScopedKeyInfoV1& info, const RaspScopedKeyNamespaceSpecV1& space);
/// Compare the entire non-authority lookup token in constant bounded work.
[[nodiscard]] bool same(const RaspScopedKeyTokenV1& left, const RaspScopedKeyTokenV1& right);
/// A zero token is never a handle or a key identity.
[[nodiscard]] bool nonzero(const RaspScopedKeyTokenV1& token);
/// Reject malformed/nonminimal/out-of-range P-256 DER before releasing provider output.
[[nodiscard]] bool valid_signature(std::span<const std::uint8_t> der);
}  // namespace rasp::keys
