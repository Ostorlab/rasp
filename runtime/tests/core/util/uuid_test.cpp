/// Tests for Uuid, random_uuid and to_string.

#include "rasp/util/uuid.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <ranges>
#include <string>
#include <string_view>

namespace rasp {
namespace {

/// Whether `c` is a lowercase hex digit.
[[nodiscard]] bool is_lower_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

/// Whether `c` fits `shape`: x is any hex digit, y is 8, 9, a or b, and any other character must match exactly.
[[nodiscard]] bool matches(char c, char shape) {
  switch (shape) {
    case 'x':
      return is_lower_hex(c);
    case 'y':
      return c == '8' || c == '9' || c == 'a' || c == 'b';
    default:
      return c == shape;
  }
}

/// Whether `text` has the shape of a version 4 UUID.
[[nodiscard]] bool is_version4_uuid(std::string_view text) {
  constexpr std::string_view kShape = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
  return std::ranges::equal(text, kShape, matches);
}

/// How many UUIDs the tests that check random_uuid's output make.
constexpr int kUuidCount = 1000;

TEST(Uuid, randomUuid_whenCalledManyTimes_alwaysReturnsAVersion4Uuid) {
  for (int i = 0; i < kUuidCount; ++i) {
    const std::string text = to_string(random_uuid());
    ASSERT_TRUE(is_version4_uuid(text)) << text;
  }
}

TEST(Uuid, randomUuid_whenCalledManyTimes_variesEveryByte) {
  const Uuid first = random_uuid();
  std::array<bool, 16> varies{};
  for (int i = 0; i < kUuidCount; ++i) {
    const Uuid uuid = random_uuid();
    for (auto [changed, byte, first_byte] : std::views::zip(varies, uuid.bytes, first.bytes)) {
      if (byte != first_byte) {
        changed = true;
      }
    }
  }

  std::size_t index = 0;
  for (const bool changed : varies) {
    EXPECT_TRUE(changed) << "byte " << index << " never changed";
    ++index;
  }
}

TEST(Uuid, randomUuid_whenCalledTwice_returnsDifferentUuids) { EXPECT_NE(random_uuid(), random_uuid()); }

TEST(Uuid, toString_whenGivenKnownBytes_writesThemAsLowercaseHexInGroups) {
  constexpr Uuid kUuid{
      .bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  };

  EXPECT_EQ(to_string(kUuid), "00112233-4455-6677-8899-aabbccddeeff");
}

}  // namespace
}  // namespace rasp
