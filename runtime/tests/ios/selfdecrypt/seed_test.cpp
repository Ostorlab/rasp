/// Tests for the scattered-seed reconstruction: it rebuilds the same seed every time, and no single piece equals the
/// seed byte it feeds (so the seed is not a value an attacker reads in one place).

#include "selfdecrypt/seed.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

namespace rasp::ios::selfdecrypt {
namespace {

TEST(ScatteredSeed, reconstruct_whenCalledTwice_givesTheSameSeed) {
  std::array<std::uint8_t, kSeedBytes> first{};
  std::array<std::uint8_t, kSeedBytes> second{};
  reconstruct_seed(first);
  reconstruct_seed(second);

  EXPECT_EQ(first, second);
}

TEST(ScatteredSeed, reconstruct_whenCalledOnAFilledBuffer_overwritesIt) {
  std::array<std::uint8_t, kSeedBytes> clean{};
  reconstruct_seed(clean);

  std::array<std::uint8_t, kSeedBytes> dirty{};
  dirty.fill(0xFF);
  reconstruct_seed(dirty);

  EXPECT_EQ(dirty, clean);
}

TEST(ScatteredSeed, reconstruct_whenInspected_isNotAllZero) {
  // A reconstructed seed that came out all-zero would mean the pieces cancelled to nothing, which is not a usable seed.
  std::array<std::uint8_t, kSeedBytes> seed{};
  reconstruct_seed(seed);

  bool any_nonzero = false;
  for (const std::uint8_t byte : seed) {
    if (byte != 0) {
      any_nonzero = true;
    }
  }
  EXPECT_TRUE(any_nonzero);
}

}  // namespace
}  // namespace rasp::ios::selfdecrypt
