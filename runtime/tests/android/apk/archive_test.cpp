/// Tests for read_stored_entry, against an APK the tests build.

#include "apk/archive.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "support/files.h"
#include "support/zip.h"

namespace rasp::android::apk {
namespace {

using test_support::StoredEntry;
using test_support::TemporaryDirectory;
using test_support::write_file;
using test_support::zip_with_stored_entries;

/// The entries of the APK the tests read.
constexpr std::array kEntries{
    StoredEntry{.name = "assets/rasp/build_id", .content = "build"},
    StoredEntry{.name = "assets/rasp/plugin-config/example", .content = "four"},
};

/// The entry the tests read.
constexpr std::string_view kConfigEntry = "assets/rasp/plugin-config/example";

/// Writes the APK of kEntries in a temporary directory of its own.
class ArchiveTest : public testing::Test {
 protected:
  /// Writes the APK.
  ///
  /// @return The APK's path, or empty when the write failed.
  [[nodiscard]] std::string write_apk() const {
    const std::string path = directory_.path() + "/base.apk";
    return write_file(path, zip_with_stored_entries(kEntries)) ? path : std::string();
  }

 private:
  /// The directory of the APK.
  TemporaryDirectory directory_;
};

/// The text of `bytes`.
///
/// @param bytes The bytes of an entry.
/// @return The same bytes, as a string.
[[nodiscard]] std::string text(const std::vector<std::uint8_t>& bytes) { return {bytes.begin(), bytes.end()}; }

TEST_F(ArchiveTest, readStoredEntry_whenNoLimitIsGiven_returnsTheEntry) {
  const std::optional<std::vector<std::uint8_t>> data = read_stored_entry(write_apk(), kConfigEntry);

  ASSERT_TRUE(data.has_value());
  EXPECT_EQ(text(*data), "four");
}

TEST_F(ArchiveTest, readStoredEntry_whenTheEntryFitsTheLimit_returnsTheEntry) {
  const std::optional<std::vector<std::uint8_t>> data = read_stored_entry(write_apk(), kConfigEntry, 4);

  ASSERT_TRUE(data.has_value());
  EXPECT_EQ(text(*data), "four");
}

TEST_F(ArchiveTest, readStoredEntry_whenTheEntryIsLargerThanTheLimit_returnsNothing) {
  EXPECT_FALSE(read_stored_entry(write_apk(), kConfigEntry, 3).has_value());
}

TEST_F(ArchiveTest, readStoredEntry_whenTheEntryIsAbsent_returnsNothing) {
  EXPECT_FALSE(read_stored_entry(write_apk(), "assets/rasp/plugin-config/other", 4).has_value());
}

}  // namespace
}  // namespace rasp::android::apk
