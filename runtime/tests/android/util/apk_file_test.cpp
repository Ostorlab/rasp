/// Tests for read_library_file: reading a native library from a plain path and from a stored entry inside an APK. The
/// tests build a minimal zip with one uncompressed entry so the entry resolution can be driven without a real APK.

#include "util/apk_file.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>

#include "support/files.h"

namespace rasp::android::util {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// The largest library read in the tests.
constexpr std::size_t kLimit = std::size_t{1} << 20U;

/// Appends `value` as `width` little-endian bytes to `out`.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): the value and its width are distinct, and this is a test
// helper.
void append_le(std::string& out, std::uint64_t value, std::size_t width) {
  for (std::size_t index = 0; index < width; ++index) {
    out.push_back(static_cast<char>((value >> (8U * index)) & 0xFFU));
  }
}

/// Builds a zip holding one stored (uncompressed) entry named `name` with the bytes `content`. The layout is a local
/// file header and the data, then a central directory with one header, then the End Of Central Directory record.
[[nodiscard]] std::string zip_with_stored_entry(std::string_view name, std::string_view content) {
  std::string zip;

  const std::uint32_t local_header_offset = 0;
  // Local file header.
  append_le(zip, 0x04034B50, 4);      // signature
  append_le(zip, 20, 2);              // version needed
  append_le(zip, 0, 2);               // flags
  append_le(zip, 0, 2);               // method: stored
  append_le(zip, 0, 2);               // mod time
  append_le(zip, 0, 2);               // mod date
  append_le(zip, 0, 4);               // crc-32 (unchecked by the reader)
  append_le(zip, content.size(), 4);  // compressed size
  append_le(zip, content.size(), 4);  // uncompressed size
  append_le(zip, name.size(), 2);     // name length
  append_le(zip, 0, 2);               // extra length
  zip.append(name);
  zip.append(content);

  const auto central_offset = static_cast<std::uint32_t>(zip.size());
  // Central directory file header.
  append_le(zip, 0x02014B50, 4);           // signature
  append_le(zip, 20, 2);                   // version made by
  append_le(zip, 20, 2);                   // version needed
  append_le(zip, 0, 2);                    // flags
  append_le(zip, 0, 2);                    // method: stored
  append_le(zip, 0, 2);                    // mod time
  append_le(zip, 0, 2);                    // mod date
  append_le(zip, 0, 4);                    // crc-32
  append_le(zip, content.size(), 4);       // compressed size
  append_le(zip, content.size(), 4);       // uncompressed size
  append_le(zip, name.size(), 2);          // name length
  append_le(zip, 0, 2);                    // extra length
  append_le(zip, 0, 2);                    // comment length
  append_le(zip, 0, 2);                    // disk number
  append_le(zip, 0, 2);                    // internal attributes
  append_le(zip, 0, 4);                    // external attributes
  append_le(zip, local_header_offset, 4);  // local header offset
  zip.append(name);

  const auto central_size = static_cast<std::uint32_t>(zip.size() - central_offset);
  // End Of Central Directory record.
  append_le(zip, 0x06054B50, 4);      // signature
  append_le(zip, 0, 2);               // disk number
  append_le(zip, 0, 2);               // disk with central directory
  append_le(zip, 1, 2);               // entries on this disk
  append_le(zip, 1, 2);               // total entries
  append_le(zip, central_size, 4);    // central directory size
  append_le(zip, central_offset, 4);  // central directory offset
  append_le(zip, 0, 2);               // comment length
  return zip;
}

TEST(ApkFile, readLibraryFile_whenPathIsAPlainFile_readsItWhole) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/librasp.so";
  ASSERT_TRUE(write_file(path, "plain library bytes"));

  EXPECT_EQ(read_library_file(path, kLimit), "plain library bytes");
}

TEST(ApkFile, readLibraryFile_whenPathIsAStoredApkEntry_readsTheEntryBytes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string apk = directory.path() + "/base.apk";
  const std::string_view entry = "lib/arm64-v8a/librasp.so";
  const std::string_view content = "the library's ELF bytes";
  ASSERT_TRUE(write_file(apk, zip_with_stored_entry(entry, content)));

  EXPECT_EQ(read_library_file(apk + "!/" + std::string(entry), kLimit), content);
}

TEST(ApkFile, readLibraryFile_whenTheEntryIsEmpty_readsEmptyBytes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string apk = directory.path() + "/base.apk";
  ASSERT_TRUE(write_file(apk, zip_with_stored_entry("lib/arm64-v8a/librasp.so", "")));

  EXPECT_EQ(read_library_file(apk + "!/lib/arm64-v8a/librasp.so", kLimit), "");
}

TEST(ApkFile, readLibraryFile_whenTheEntryIsMissing_reportsNothing) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string apk = directory.path() + "/base.apk";
  ASSERT_TRUE(write_file(apk, zip_with_stored_entry("lib/arm64-v8a/librasp.so", "bytes")));

  EXPECT_FALSE(read_library_file(apk + "!/lib/arm64-v8a/missing.so", kLimit).has_value());
}

TEST(ApkFile, readLibraryFile_whenTheApkDoesNotExist_reportsNothing) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_FALSE(read_library_file(directory.path() + "/missing.apk!/lib/librasp.so", kLimit).has_value());
}

TEST(ApkFile, readLibraryFile_whenTheApkIsNotAZip_reportsNothing) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string apk = directory.path() + "/base.apk";
  ASSERT_TRUE(write_file(apk, "not a zip file at all"));

  EXPECT_FALSE(read_library_file(apk + "!/lib/librasp.so", kLimit).has_value());
}

TEST(ApkFile, readLibraryFile_whenTheEntryIsLargerThanTheLimit_reportsNothing) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/librasp.so";
  ASSERT_TRUE(write_file(path, std::string(64, 'a')));

  EXPECT_FALSE(read_library_file(path, 32).has_value());
}

}  // namespace
}  // namespace rasp::android::util
