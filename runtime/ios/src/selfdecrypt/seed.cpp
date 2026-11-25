/// scattered_seed: see seed.h. The seed is reconstructed from many small constants rather than read from one section,
/// so there is no contiguous plaintext seed to dump from the binary.
///
/// The per-build constant pieces live in a generated header (seed_pieces.inc). Until the build generates one, a default
/// development set is used so the runtime and tests build; a release build replaces it per build so each ships a
/// different scattered seed. Every piece is a separate constant expression, which the obfuscator's opaque-constants
/// pass rewrites on its own, so the reconstruction has no single value an attacker can read in one place.

#include "selfdecrypt/seed.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace rasp::ios::selfdecrypt {

namespace {

/// One scattered piece of the seed: which seed byte it contributes to, and the value it XORs in. Several pieces target
/// the same byte, so no one constant equals a seed byte and the byte is only correct once every piece is folded in.
struct SeedPiece {
  /// The seed byte this piece contributes to.
  std::uint8_t index;
  /// The value XORed into that byte.
  std::uint8_t value;
};

// The per-build scatter. A real release generates this from a random seed, emitting pieces in a shuffled order with
// several pieces per byte. This default development set is deterministic so the runtime and tests build; it is not a
// secret and is expected to be replaced per build.
#if __has_include("selfdecrypt/seed_pieces.inc")
#include "selfdecrypt/seed_pieces.inc"
#else
/// The default development scatter: two pieces per byte whose XOR is (index * 37 + 11) mod 256.
[[nodiscard]] constexpr std::array<SeedPiece, kSeedBytes * 2> default_pieces() {
  std::array<SeedPiece, kSeedBytes * 2> pieces{};
  for (std::size_t i = 0; i < kSeedBytes; i++) {
    const auto target = static_cast<std::uint8_t>(((i * 37U) + 11U) & 0xFFU);
    const auto half = static_cast<std::uint8_t>(0x5AU + i);
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index): i is bounded by kSeedBytes.
    pieces[2 * i] = SeedPiece{.index = static_cast<std::uint8_t>(i), .value = half};
    pieces[(2 * i) + 1] =
        SeedPiece{.index = static_cast<std::uint8_t>(i), .value = static_cast<std::uint8_t>(target ^ half)};
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index)
  }
  return pieces;
}
constexpr auto kSeedPieces = default_pieces();
#endif

}  // namespace

void reconstruct_seed(std::array<std::uint8_t, kSeedBytes>& out) {
  out.fill(0);
  for (const SeedPiece& piece : kSeedPieces) {
    if (piece.index < kSeedBytes) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index): piece.index is bounds-checked above.
      out[piece.index] = static_cast<std::uint8_t>(out[piece.index] ^ piece.value);
    }
  }
}

}  // namespace rasp::ios::selfdecrypt
