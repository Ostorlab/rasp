/// Tests for read_library_file: reading a native library from a plain path and from a stored entry inside an APK. The
/// tests build a minimal zip with one uncompressed entry so the entry resolution can be driven without a real APK.

#include "util/apk_file.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "support/files.h"
#include "support/zip.h"

namespace rasp::android::util {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;
using test_support::zip_with_stored_entry;

/// The largest library read in the tests.
constexpr std::size_t kLimit = std::size_t{1} << 20U;

/// The bytes of `text`, the type read_library_file returns, so a result can be compared to an expected value.
[[nodiscard]] std::vector<std::uint8_t> bytes(std::string_view text) { return {text.begin(), text.end()}; }

TEST(ApkFile, readLibraryFile_whenPathIsAPlainFile_readsItWhole) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = directory.path() + "/librasp.so";
  ASSERT_TRUE(write_file(path, "plain library bytes"));

  EXPECT_EQ(read_library_file(path, kLimit), bytes("plain library bytes"));
}

TEST(ApkFile, readLibraryFile_whenPathIsAStoredApkEntry_readsTheEntryBytes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string apk = directory.path() + "/base.apk";
  const std::string_view entry = "lib/arm64-v8a/librasp.so";
  const std::string_view content = "the library's ELF bytes";
  ASSERT_TRUE(write_file(apk, zip_with_stored_entry(entry, content)));

  EXPECT_EQ(read_library_file(apk + "!/" + std::string(entry), kLimit), bytes(content));
}

TEST(ApkFile, readLibraryFile_whenTheEntryIsEmpty_readsEmptyBytes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string apk = directory.path() + "/base.apk";
  ASSERT_TRUE(write_file(apk, zip_with_stored_entry("lib/arm64-v8a/librasp.so", "")));

  EXPECT_EQ(read_library_file(apk + "!/lib/arm64-v8a/librasp.so", kLimit), bytes(""));
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
