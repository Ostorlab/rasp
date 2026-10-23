/// Tests for loader_dex: the embedded bytes must be a complete dex that defines the loader class.

#include "loader/loader_dex.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::android::loader {
namespace {

/// The size of a dex header, in bytes.
constexpr std::size_t kHeaderSize = 0x70;

/// Reads a little-endian 32-bit value.
///
/// @param data The bytes to read from. They must hold at least `offset + 4` bytes.
/// @param offset Where the value starts in `data`.
/// @return The value.
[[nodiscard]] std::uint32_t read_u32(const std::vector<std::uint8_t>& data, std::size_t offset) {
  return static_cast<std::uint32_t>(data[offset]) | (static_cast<std::uint32_t>(data[offset + 1U]) << 8U) |
         (static_cast<std::uint32_t>(data[offset + 2U]) << 16U) |
         (static_cast<std::uint32_t>(data[offset + 3U]) << 24U);
}

/// The type descriptor of a class, such as `Lcom/example/Main;` for `com.example.Main`.
///
/// @param binary_name The binary name of the class.
/// @return The descriptor.
[[nodiscard]] std::string descriptor_of(std::string_view binary_name) {
  std::string descriptor = "L";
  for (const char character : binary_name) {
    descriptor.push_back(character == '.' ? '/' : character);
  }
  descriptor.push_back(';');
  return descriptor;
}

/// Whether some bytes appear in a byte buffer.
///
/// @param haystack The buffer to search.
/// @param needle The bytes to look for.
/// @return Whether `needle`'s bytes appear, in order and next to each other, in `haystack`.
[[nodiscard]] bool contains(const std::vector<std::uint8_t>& haystack, std::string_view needle) {
  const std::vector<std::uint8_t> bytes(needle.begin(), needle.end());
  return !std::ranges::search(haystack, bytes).empty();
}

TEST(LoaderDex, loaderDex_whenCalled_returnsACompleteDex) {
  const std::vector<std::uint8_t> dex = loader_dex();
  ASSERT_GE(dex.size(), kHeaderSize);
  const std::array<std::uint8_t, 4> magic = {'d', 'e', 'x', '\n'};
  EXPECT_TRUE(std::ranges::equal(magic, std::vector<std::uint8_t>(dex.begin(), dex.begin() + 4)));
  EXPECT_EQ(dex[7], 0U);
  EXPECT_EQ(read_u32(dex, 32U), static_cast<std::uint32_t>(dex.size()));
  EXPECT_EQ(read_u32(dex, 36U), kHeaderSize);
  EXPECT_EQ(read_u32(dex, 40U), 0x12345678U);
}

TEST(LoaderDex, loaderDex_whenCalled_definesTheLoaderClass) {
  EXPECT_TRUE(contains(loader_dex(), descriptor_of(kLoaderClassName)));
}

}  // namespace
}  // namespace rasp::android::loader
