#include "util/memory_map.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string_view>
#include <vector>

namespace rasp::android::util {
namespace {

TEST(MemoryMap, parseMemoryMap_whenTheLineMapsAFile_readsEveryField) {
  const std::vector<Mapping> mappings =
      parse_memory_map("7f0000020000-7f0000120000 r-xp 0001a000 fd:00 200  /apex/com.android.runtime/bionic/libc.so\n");

  ASSERT_EQ(mappings.size(), 1U);
  const Mapping& mapping = mappings.front();
  EXPECT_EQ(mapping.start, std::uintptr_t{0x7f0000020000});
  EXPECT_EQ(mapping.end, std::uintptr_t{0x7f0000120000});
  EXPECT_TRUE(mapping.readable);
  EXPECT_TRUE(mapping.executable);
  EXPECT_FALSE(mapping.shared);
  EXPECT_EQ(mapping.offset, 0x1a000U);
  EXPECT_EQ(mapping.device, "fd:00");
  EXPECT_EQ(mapping.inode, 200U);
  EXPECT_EQ(mapping.pathname, "/apex/com.android.runtime/bionic/libc.so");
  EXPECT_FALSE(mapping.deleted);
  EXPECT_EQ(mapping.line,
            "7f0000020000-7f0000120000 r-xp 0001a000 fd:00 200  /apex/com.android.runtime/bionic/libc.so");
}

TEST(MemoryMap, parseMemoryMap_whenTheFileWasDeleted_keepsThePathnameAndMarksIt) {
  const std::vector<Mapping> mappings =
      parse_memory_map("54c00000-56c00000 r-xs 02000000 00:01 3  /memfd:jit-cache (deleted)");

  ASSERT_EQ(mappings.size(), 1U);
  EXPECT_EQ(mappings.front().pathname, "/memfd:jit-cache");
  EXPECT_TRUE(mappings.front().deleted);
  EXPECT_TRUE(mappings.front().shared);
}

TEST(MemoryMap, parseMemoryMap_whenTheMemoryIsAnonymous_hasNoPathname) {
  const std::vector<Mapping> mappings = parse_memory_map("7f0000200000-7f0000400000 rw-p 00000000 00:00 0\n");

  ASSERT_EQ(mappings.size(), 1U);
  EXPECT_TRUE(mappings.front().pathname.empty());
  EXPECT_FALSE(mappings.front().executable);
}

TEST(MemoryMap, parseMemoryMap_whenALineIsMalformed_leavesOnlyItOut) {
  const std::vector<Mapping> mappings = parse_memory_map(
      "not a mapping\n"
      "7f10-7f00 r-xp 00000000 00:00 0\n"
      "7f00-7f10 r-x 00000000 00:00 0\n"
      "7f00-7f10 r-xp 0000000g 00:00 0\n"
      "7f00-7f10 r-xp 00000000 00:00 0 [vdso]\n");

  ASSERT_EQ(mappings.size(), 1U);
  EXPECT_EQ(mappings.front().pathname, "[vdso]");
}

TEST(MemoryMap, findMapping_whenTheAddressIsInsideAMapping_findsIt) {
  const std::vector<Mapping> mappings = parse_memory_map(
      "1000-2000 r--p 00000000 00:00 0\n"
      "3000-4000 r-xp 00000000 00:00 0\n");

  ASSERT_NE(find_mapping(mappings, 0x3000), nullptr);
  EXPECT_EQ(find_mapping(mappings, 0x3000)->start, std::uintptr_t{0x3000});
  ASSERT_NE(find_mapping(mappings, 0x1fff), nullptr);
  EXPECT_EQ(find_mapping(mappings, 0x1fff)->start, std::uintptr_t{0x1000});
}

TEST(MemoryMap, findMapping_whenTheAddressIsInNoMapping_findsNothing) {
  const std::vector<Mapping> mappings = parse_memory_map(
      "1000-2000 r--p 00000000 00:00 0\n"
      "3000-4000 r-xp 00000000 00:00 0\n");

  EXPECT_EQ(find_mapping(mappings, 0xfff), nullptr);
  EXPECT_EQ(find_mapping(mappings, 0x2000), nullptr);
  EXPECT_EQ(find_mapping(mappings, 0x4000), nullptr);
}

}  // namespace
}  // namespace rasp::android::util
