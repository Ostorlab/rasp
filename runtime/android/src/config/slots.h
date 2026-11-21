/// The runtime's per-app values, which the packer writes into slots of the runtime's own code, and their readers.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "rasp/config.h"

namespace rasp::android::config {

inline constexpr std::size_t kBuildIdSlotSize = 128;
inline constexpr std::size_t kChecksSlotSize = 16;
inline constexpr std::size_t kProgramSlotSize = 512;
inline constexpr std::size_t kDigestSlotSize = 32;
inline constexpr std::size_t kPadSlotSize = 32;
inline constexpr std::size_t kDecoySlotSize = 32;
inline constexpr std::size_t kShareSlotSize = 32;

/// A 32-byte value of a slot.
using SlotKey = std::array<std::uint8_t, 32>;

/// Decodes the bytes of the build-id slot and the checks slot: the id up to its first zero byte, and the mask in the
/// checks slot's first eight bytes, least significant first.
[[nodiscard]] Config decode_config(std::span<const std::uint8_t> build_id, std::span<const std::uint8_t> checks);

/// The keystore share `masked` holds under `pad`.
[[nodiscard]] SlotKey unmask_share(const SlotKey& masked, const SlotKey& pad);

/// Reads the build id and the checks mask the packer wrote.
///
/// @return The config, with every field empty when the library was never packed.
[[nodiscard]] Config read_config();

/// The fold program the packer wrote, or nothing when the library was never packed.
[[nodiscard]] std::optional<std::array<std::uint8_t, kProgramSlotSize>> fold_program();

/// The expected plaintext `.text` digest the packer wrote, or nothing when the library was never packed.
[[nodiscard]] std::optional<SlotKey> text_digest();

/// The keystore share the packer wrote, or nothing when the library was never packed.
[[nodiscard]] std::optional<SlotKey> keystore_share();

/// The bytes the key schedule's region record digests: every slot but the share, in a fixed order.
///
/// @return The bytes, or nothing when the library was never packed.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> region();

}  // namespace rasp::android::config
