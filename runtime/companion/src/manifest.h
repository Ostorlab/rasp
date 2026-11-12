/// Fixed versioned private manifest; no transaction data, credentials or private keys.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "rasp/scoped_key.h"

namespace rasp::keys {
/// Persistent key states; reserved keys are never usable after interrupted creation.
enum class KeyState : std::uint8_t { kEmpty = 0, kReserved = 1, kLive = 2, kDeletePending = 3 };
/// One explicitly owned key identity and its immutable public profile.
struct Record {
  KeyState state;
  std::array<std::uint8_t, 3> state_padding;
  std::uint32_t reserved;
  RaspScopedKeyInfoV1 info;
};
/// Owned fixed manifest; application hash and installation generation are separate facts.
struct Manifest {
  RaspScopedKeyTokenV1 generation;
  std::array<std::uint8_t, 32> application_sha256;
  std::array<Record, 32> records;
};
/// Exact file size including zero padding and corruption digest.
inline constexpr std::size_t kManifestBytes = 8192;
/// Serialize a complete canonical manifest into a reserved scratch arena.
[[nodiscard]] bool encode_manifest(const Manifest& manifest, std::span<std::uint8_t> output);
/// Reject corruption, duplicate identities, unknown states and noncanonical padding.
[[nodiscard]] bool decode_manifest(std::span<const std::uint8_t> input, Manifest& output);
}  // namespace rasp::keys
