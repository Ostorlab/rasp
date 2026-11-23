/// Tests for HiddenString: compile-time XOR-masked string literals used so the iOS checks' artifact paths do not
/// appear in the shipped framework as plaintext.

#include "util/hidden_string.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace rasp::ios::util {
namespace {

TEST(HiddenStringTest, testReveal_whenGivenLiteral_shouldReturnExactPlaintext) {
  constexpr HiddenString hidden{"/Applications/Cydia.app"};

  const std::string revealed = hidden.reveal();

  EXPECT_EQ(revealed, std::string("/Applications/Cydia.app"));
}

TEST(HiddenStringTest, testReveal_whenEmptyLiteral_shouldReturnEmptyString) {
  constexpr HiddenString hidden{""};

  const std::string revealed = hidden.reveal();

  EXPECT_EQ(revealed, std::string());
}

TEST(HiddenStringTest, testReveal_whenCalledTwice_shouldReturnEqualStrings) {
  constexpr HiddenString hidden{"/var/jb/usr/bin/sshd"};

  const std::string first = hidden.reveal();
  const std::string second = hidden.reveal();

  EXPECT_EQ(first, second);
}

TEST(MaskByteTest, testMaskByte_whenAppliedTwice_shouldReturnOriginalByte) {
  for (int value = 0; value < 256; ++value) {
    const auto original = static_cast<std::uint8_t>(value);

    const std::uint8_t once = mask_byte(original, 3);
    const std::uint8_t twice = mask_byte(once, 3);

    EXPECT_EQ(twice, original);
  }
}

TEST(MaskByteTest, testMaskByte_whenSameByteDifferentIndex_shouldDifferByPosition) {
  const std::uint8_t at_zero = mask_byte(static_cast<std::uint8_t>('a'), 0);
  const std::uint8_t at_one = mask_byte(static_cast<std::uint8_t>('a'), 1);

  EXPECT_NE(at_zero, at_one);
}

TEST(RevealAllTest, testRevealAll_whenMixedLengths_shouldRevealAllInOrder) {
  const std::vector<std::string> revealed =
      reveal_all(HiddenString{"/bin/sh"}, HiddenString{"/Applications/Sileo.app"}, HiddenString{"/jb"});

  ASSERT_EQ(revealed.size(), 3U);
  EXPECT_EQ(revealed[0], std::string("/bin/sh"));
  EXPECT_EQ(revealed[1], std::string("/Applications/Sileo.app"));
  EXPECT_EQ(revealed[2], std::string("/jb"));
}

}  // namespace
}  // namespace rasp::ios::util
