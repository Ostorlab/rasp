#include "util/property_area.h"

#include <array>
#include <bit>
#include <charconv>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "rasp/util/read_file.h"
#include "support/files.h"
#include "support/property_files.h"

namespace rasp::android::util {
namespace {

using test_support::FileProperty;
using test_support::InfoNode;
using test_support::property_file;
using test_support::property_info;
using test_support::TemporaryDirectory;
using test_support::write_file;

[[nodiscard]] std::string hex(std::uintptr_t value) {
  std::array<char, 2 * sizeof(value)> digits{};
  const auto [end, error] = std::to_chars(digits.data(), std::to_address(digits.end()), value, 16);
  return error == std::errc{} ? std::string(digits.data(), end) : std::string();
}

/// The property files of the tests: build properties, boot properties and a debug property in files of their own.
const std::array<std::string, 3> kContexts = {
    "u:object_r:build_prop:s0",
    "u:object_r:bootloader_prop:s0",
    "u:object_r:userdebug_or_eng_prop:s0",
};

/// The index of the tests: `ro.*` in the build file, `ro.boot.*` in the boot file, and `ro.debuggable` exactly in the
/// debug file.
[[nodiscard]] std::vector<InfoNode> test_index() {
  return {
      {.name = "", .context = std::nullopt, .prefixes = {}, .exact_matches = {}, .children = {1}},
      {.name = "ro", .context = 0, .prefixes = {}, .exact_matches = {{"debuggable", 2}}, .children = {2}},
      {.name = "boot", .context = 1, .prefixes = {}, .exact_matches = {}, .children = {}},
  };
}

TEST(PropertyArea, find_whenTheFileHoldsTheProperty_readsItsValueAndSerial) {
  const auto properties = std::to_array<FileProperty>({
      {.name = "ro.build.type", .value = "user", .counter = 0},
      {.name = "ro.build.tags", .value = "release-keys", .counter = 0},
      {.name = "ro.hardware", .value = "qcom", .counter = 0},
  });
  const std::string file = property_file(properties);

  EXPECT_EQ(PropertyFile(file).find("ro.build.tags"), (AreaProperty{.value = "release-keys", .serial = 12U << 24U}));
  EXPECT_EQ(PropertyFile(file).find("ro.hardware"), (AreaProperty{.value = "qcom", .serial = 4U << 24U}));
}

TEST(PropertyArea, find_whenTheValueIsLong_readsItWhole) {
  const std::string value(200, 'x');
  const std::array<FileProperty, 1> properties = {{{.name = "ro.build.fingerprint", .value = value, .counter = 0}}};
  const std::string file = property_file(properties);

  const std::optional<AreaProperty> property = PropertyFile(file).find("ro.build.fingerprint");

  ASSERT_TRUE(property.has_value());
  EXPECT_EQ(property->value, value);
}

TEST(PropertyArea, find_whenTheValueIsEmpty_readsIt) {
  const std::array<FileProperty, 1> properties = {{{.name = "ro.kernel.qemu", .value = "", .counter = 0}}};
  const std::string file = property_file(properties);

  EXPECT_EQ(PropertyFile(file).find("ro.kernel.qemu"), (AreaProperty{.value = "", .serial = 0}));
}

TEST(PropertyArea, find_whenTheNameIsMissingOrOnlyAPrefix_findsNothing) {
  const std::array<FileProperty, 1> properties = {{{.name = "ro.build.type", .value = "user", .counter = 0}}};
  const std::string file = property_file(properties);

  EXPECT_FALSE(PropertyFile(file).find("ro.build.tags").has_value());
  EXPECT_FALSE(PropertyFile(file).find("ro.build").has_value());
  EXPECT_FALSE(PropertyFile(file).find("ro.build.type.extra").has_value());
  EXPECT_FALSE(PropertyFile(file).find("ro..type").has_value());
}

TEST(PropertyArea, find_whenTheMagicIsWrong_findsNothing) {
  const std::array<FileProperty, 1> properties = {{{.name = "ro.build.type", .value = "user", .counter = 0}}};
  std::string file = property_file(properties);
  file[8] = 'X';

  EXPECT_FALSE(PropertyFile(file).find("ro.build.type").has_value());
}

TEST(PropertyArea, find_whenAnOffsetPointsOutsideTheFile_findsNothing) {
  const std::array<FileProperty, 1> properties = {{{.name = "ro.build.type", .value = "user", .counter = 0}}};
  std::string file = property_file(properties);
  test_support::property_files::put_u32(file, 128 + 16, 0x7FFFFFF0U);

  EXPECT_FALSE(PropertyFile(file).find("ro.build.type").has_value());
}

TEST(PropertyArea, find_whenSiblingsFormACycle_stopsAndFindsNothing) {
  const std::array<FileProperty, 1> properties = {{{.name = "ro.x", .value = "1", .counter = 0}}};
  std::string file = property_file(properties);
  const std::uint32_t first = test_support::property_files::get_u32(file, 128 + 16);
  test_support::property_files::put_u32(file, 128 + first + 12, first);

  EXPECT_FALSE(PropertyFile(file).find("zz.x").has_value());
}

TEST(PropertyArea, find_whenTheValueStaysBeingWritten_findsNothing) {
  const std::array<FileProperty, 1> properties = {{{.name = "ro.build.type", .value = "user", .counter = 1}}};
  const std::string file = property_file(properties);

  EXPECT_FALSE(PropertyFile(file).find("ro.build.type").has_value());
}

TEST(PropertyArea, wasRewritten_whenTheCounterHasCountedAWrite_saysSo) {
  EXPECT_FALSE(was_rewritten(4U << 24U));
  EXPECT_FALSE(was_rewritten((4U << 24U) | (1U << 16U)));
  EXPECT_FALSE(was_rewritten(1U));
  EXPECT_TRUE(was_rewritten((4U << 24U) | 2U));
  EXPECT_TRUE(was_rewritten((1U << 16U) | 4U));
}

TEST(PropertyArea, fileOf_whenANodeOrAnExactMatchNamesTheFile_findsIt) {
  const std::string info = property_info(kContexts, test_index());

  EXPECT_EQ(PropertyIndex(info).file_of("ro.build.tags"), "u:object_r:build_prop:s0");
  EXPECT_EQ(PropertyIndex(info).file_of("ro.boot.verifiedbootstate"), "u:object_r:bootloader_prop:s0");
  EXPECT_EQ(PropertyIndex(info).file_of("ro.debuggable"), "u:object_r:userdebug_or_eng_prop:s0");
}

TEST(PropertyArea, fileOf_whenAPrefixMatches_prefersIt) {
  std::vector<InfoNode> index = test_index();
  index[1].prefixes = {{"vendor.", 1}};
  const std::string info = property_info(kContexts, index);

  EXPECT_EQ(PropertyIndex(info).file_of("ro.vendor.build.id"), "u:object_r:bootloader_prop:s0");
  EXPECT_EQ(PropertyIndex(info).file_of("ro.vendo"), "u:object_r:build_prop:s0");
}

TEST(PropertyArea, fileOf_whenNothingNamesAFile_findsNothing) {
  const std::string info = property_info(kContexts, test_index());

  EXPECT_FALSE(PropertyIndex(info).file_of("persist.sys.locale").has_value());
  EXPECT_FALSE(PropertyIndex(info).file_of("ro").has_value());
}

TEST(PropertyArea, fileOf_whenTheIndexIsForANewerReader_findsNothing) {
  std::string info = property_info(kContexts, test_index());
  test_support::property_files::put_u32(info, 4, 2);

  EXPECT_FALSE(PropertyIndex(info).file_of("ro.build.tags").has_value());
}

TEST(PropertyArea, fileOf_whenAContextIndexIsOutOfRange_findsNothing) {
  std::vector<InfoNode> index = test_index();
  index[1].context = 7;
  const std::string info = property_info(kContexts, index);

  EXPECT_FALSE(PropertyIndex(info).file_of("ro.build.tags").has_value());
}

/// A property folder as the platform lays it out: the index and the three property files of the tests.
class PropertyAreasTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_FALSE(directory_.path().empty());
    ASSERT_TRUE(write_file(directory_.path() + "/property_info", property_info(kContexts, test_index())));
    const auto build = std::to_array<FileProperty>({
        {.name = "ro.build.tags", .value = "release-keys", .counter = 0},
        {.name = "ro.build.type", .value = "user", .counter = 2},
    });
    ASSERT_TRUE(write_file(directory_.path() + "/" + kContexts[0], property_file(build)));
    const std::array<FileProperty, 1> boot = {{{.name = "ro.boot.verifiedbootstate", .value = "green", .counter = 0}}};
    ASSERT_TRUE(write_file(directory_.path() + "/" + kContexts[1], property_file(boot)));
  }

  /// A reader of the test's folder, whose memory map is `maps`.
  [[nodiscard]] PropertyAreas areas(std::string_view maps) const {
    const std::string path = directory_.path() + "/maps";
    static_cast<void>(write_file(path, maps));
    return {directory_.path(), path, rasp::util::read_file};
  }

  /// The test's folder.
  [[nodiscard]] const std::string& directory() const { return directory_.path(); }

 private:
  TemporaryDirectory directory_;
};

TEST_F(PropertyAreasTest, read_whenThePropertyIsInAFile_readsIt) {
  PropertyAreas reader = areas("");

  EXPECT_TRUE(reader.readable());
  EXPECT_EQ(reader.read("ro.build.tags"), (AreaProperty{.value = "release-keys", .serial = 12U << 24U}));
  EXPECT_EQ(reader.read("ro.boot.verifiedbootstate"), (AreaProperty{.value = "green", .serial = 5U << 24U}));
  EXPECT_EQ(reader.read("ro.build.type"), (AreaProperty{.value = "user", .serial = (4U << 24U) | 2U}));
}

TEST_F(PropertyAreasTest, read_whenThePropertysFileIsMissing_readsNothing) {
  PropertyAreas reader = areas("");

  EXPECT_FALSE(reader.read("ro.debuggable").has_value());
  EXPECT_FALSE(reader.read("ro.build.fingerprint").has_value());
}

TEST_F(PropertyAreasTest, read_whenTheFileCantBeOpenedButTheProcessMapsIt_readsTheMapping) {
  const std::array<FileProperty, 1> debug = {{{.name = "ro.debuggable", .value = "0", .counter = 0}}};
  const std::string mapped = property_file(debug);
  const auto start = std::bit_cast<std::uintptr_t>(mapped.data());
  const std::string line = hex(start) + "-" + hex(start + mapped.size()) + " r--s 00000000 00:10 41 " + directory() +
                           "/" + kContexts[2] + "\n";
  PropertyAreas reader = areas(line);

  EXPECT_EQ(reader.read("ro.debuggable"), (AreaProperty{.value = "0", .serial = 1U << 24U}));
}

TEST_F(PropertyAreasTest, readable_whenTheIndexIsMissing_saysNo) {
  PropertyAreas reader(directory() + "/missing", directory() + "/maps", rasp::util::read_file);

  EXPECT_FALSE(reader.readable());
  EXPECT_FALSE(reader.read("ro.build.tags").has_value());
}

}  // namespace
}  // namespace rasp::android::util
