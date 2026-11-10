/// Tests for the base32hex encoder against RFC 4648 section 10 test vectors and
/// edge cases.

#include "base32hex.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <vector>

namespace rasp::plugins::dns_reporting {
namespace {

// --- encoded_size ---

TEST(Base32hex, encodedSize_whenZeroBytes_returnsZero) { EXPECT_EQ(encoded_size(0), 0U); }

TEST(Base32hex, encodedSize_whenOneByte_returnsTwoCharacters) { EXPECT_EQ(encoded_size(1), 2U); }

TEST(Base32hex, encodedSize_whenTwoBytes_returnsFourCharacters) { EXPECT_EQ(encoded_size(2), 4U); }

TEST(Base32hex, encodedSize_whenThreeBytes_returnsFiveCharacters) { EXPECT_EQ(encoded_size(3), 5U); }

TEST(Base32hex, encodedSize_whenFourBytes_returnsSevenCharacters) { EXPECT_EQ(encoded_size(4), 7U); }

TEST(Base32hex, encodedSize_whenFiveBytes_returnsEightCharacters) { EXPECT_EQ(encoded_size(5), 8U); }

TEST(Base32hex, encodedSize_whenSixBytes_returnsTenCharacters) { EXPECT_EQ(encoded_size(6), 10U); }

// --- encode: RFC 4648 section 10 test vectors (base32hex, no padding) ---

TEST(Base32hex, encode_whenEmpty_returnsEmptyString) { EXPECT_EQ(encode(std::span<const std::uint8_t>{}), ""); }

TEST(Base32hex, encode_whenOneByte_returnsTwoCharacters) {
  const std::vector<std::uint8_t> data = {'f'};
  EXPECT_EQ(encode(data), "CO");
  EXPECT_EQ(encode(data).size(), encoded_size(data.size()));
}

TEST(Base32hex, encode_whenFo_returnsCorrectText) {
  const std::vector<std::uint8_t> data = {'f', 'o'};
  EXPECT_EQ(encode(data), "CPNG");
  EXPECT_EQ(encode(data).size(), encoded_size(data.size()));
}

TEST(Base32hex, encode_whenFoo_returnsCorrectText) {
  const std::vector<std::uint8_t> data = {'f', 'o', 'o'};
  EXPECT_EQ(encode(data), "CPNMU");
  EXPECT_EQ(encode(data).size(), encoded_size(data.size()));
}

TEST(Base32hex, encode_whenFoob_returnsCorrectText) {
  const std::vector<std::uint8_t> data = {'f', 'o', 'o', 'b'};
  EXPECT_EQ(encode(data), "CPNMUOG");
  EXPECT_EQ(encode(data).size(), encoded_size(data.size()));
}

TEST(Base32hex, encode_whenFooba_returnsCorrectText) {
  const std::vector<std::uint8_t> data = {'f', 'o', 'o', 'b', 'a'};
  EXPECT_EQ(encode(data), "CPNMUOJ1");
  EXPECT_EQ(encode(data).size(), encoded_size(data.size()));
}

TEST(Base32hex, encode_whenFoobar_returnsCorrectText) {
  const std::vector<std::uint8_t> data = {'f', 'o', 'o', 'b', 'a', 'r'};
  EXPECT_EQ(encode(data), "CPNMUOJ1E8");
  EXPECT_EQ(encode(data).size(), encoded_size(data.size()));
}

// --- encode: edge cases ---

TEST(Base32hex, encode_whenAllZeros_producesAllZeroCharacters) {
  const std::vector<std::uint8_t> zeros(5, 0x00);
  EXPECT_EQ(encode(zeros), "00000000");
}

TEST(Base32hex, encode_whenAllOnes_producesAllVCharacters) {
  const std::vector<std::uint8_t> ones(5, 0xFF);
  EXPECT_EQ(encode(ones), "VVVVVVVV");
}

}  // namespace
}  // namespace rasp::plugins::dns_reporting
