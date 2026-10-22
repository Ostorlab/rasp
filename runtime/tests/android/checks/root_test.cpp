/// Tests for the Android root checks.

#include "checks/root.h"

#include <array>
#include <cstddef>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// The size limit of the mount table, 1 MiB.
constexpr std::size_t kMountsLimit = std::size_t{1} << 20U;

/// Lines of a stock device's mount table, none of which mentions a root tool.
constexpr std::string_view kStockMounts =
    "/dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0\n"
    "tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0\n"
    "/dev/block/dm-1 /vendor ext4 ro,seclabel,relatime 0 0\n"
    "/dev/block/dm-5 /data f2fs rw,lazytime,seclabel,nosuid,nodev 0 0\n";

/// The observations of a mount table where `root_lines` are the mounts a root tool made and `rw_lines` the system
/// folders mounted writable.
[[nodiscard]] std::vector<Observation> mounts(const std::vector<std::string>& root_lines,
                                              const std::vector<std::string>& rw_lines = {}) {
  return {
      {.signal = "root.mounts", .source = "proc_mounts", .status = Status::kOk, .value = root_lines},
      {.signal = "root.rw_mounts", .source = "proc_mounts", .status = Status::kOk, .value = rw_lines},
  };
}

/// The observations of a mount table that couldn't be read.
[[nodiscard]] std::vector<Observation> unreadable_mounts() {
  return {
      {.signal = "root.mounts", .source = "proc_mounts", .status = Status::kError, .value = {}},
      {.signal = "root.rw_mounts", .source = "proc_mounts", .status = Status::kError, .value = {}},
  };
}

/// The root.selinux_enforcing observation that reports `enforcing`.
[[nodiscard]] Observation selinux(bool enforcing) {
  return {.signal = "root.selinux_enforcing", .source = "selinuxfs", .status = Status::kOk, .value = enforcing};
}

/// The root.build_props observation that reports `properties`.
[[nodiscard]] Observation build_props(const std::vector<std::string>& properties) {
  return {.signal = "root.build_props", .source = "system_property", .status = Status::kOk, .value = properties};
}

/// Reads the properties of a rooted phone with an unlocked bootloader, which sets every property root.build_props
/// reports.
[[nodiscard]] std::optional<std::string> read_unlocked_phone(std::string_view name) {
  constexpr auto kProperties = std::to_array<std::pair<std::string_view, std::string_view>>({
      {"ro.debuggable", "0"},
      {"ro.secure", "1"},
      {"ro.build.type", "user"},
      {"ro.build.tags", "release-keys"},
      {"ro.boot.verifiedbootstate", "orange"},
      {"ro.boot.vbmeta.device_state", "unlocked"},
      {"ro.boot.flash.locked", "0"},
  });
  for (const auto& [key, value] : kProperties) {
    if (key == name) {
      return std::string(value);
    }
  }
  return std::nullopt;
}

/// Reads the properties of an emulator, which sets no bootloader property.
[[nodiscard]] std::optional<std::string> read_emulator(std::string_view name) {
  if (name.starts_with("ro.boot.")) {
    return std::nullopt;
  }
  return read_unlocked_phone(name);
}

/// Reads properties that are all set to an empty value.
[[nodiscard]] std::optional<std::string> read_empty([[maybe_unused]] std::string_view name) { return ""; }

/// Reads properties that are all unset.
[[nodiscard]] std::optional<std::string> read_nothing([[maybe_unused]] std::string_view name) { return std::nullopt; }

TEST(Root, observePaths_whenOnePathExists_reportsItThroughBothSources) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string present = directory.path() + "/su";
  const std::string missing = directory.path() + "/missing";
  ASSERT_TRUE(write_file(present, "x"));
  const std::array<std::string_view, 2> paths = {present, missing};

  const std::vector<Observation> observations = observe_paths(paths);

  const std::vector<std::string> found = {present};
  EXPECT_EQ(observations, (std::vector<Observation>{
                              {.signal = "root.fs_paths", .source = "access", .status = Status::kOk, .value = found},
                              {.signal = "root.fs_paths", .source = "stat", .status = Status::kOk, .value = found},
                          }));
}

TEST(Root, observePaths_whenAPathIsADirectory_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string magisk = directory.path() + "/magisk";
  ASSERT_TRUE(std::filesystem::create_directory(magisk));
  const std::array<std::string_view, 1> paths = {magisk};

  const std::vector<Observation> observations = observe_paths(paths);

  const std::vector<std::string> found = {magisk};
  EXPECT_EQ(observations, (std::vector<Observation>{
                              {.signal = "root.fs_paths", .source = "access", .status = Status::kOk, .value = found},
                              {.signal = "root.fs_paths", .source = "stat", .status = Status::kOk, .value = found},
                          }));
}

TEST(Root, observePaths_whenSeveralPathsExist_reportsThemInTheGivenOrder) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string first = directory.path() + "/b";
  const std::string second = directory.path() + "/a";
  ASSERT_TRUE(write_file(first, "x"));
  ASSERT_TRUE(write_file(second, "x"));
  const std::array<std::string_view, 2> paths = {first, second};

  const std::vector<Observation> observations = observe_paths(paths);

  const std::vector<std::string> found = {first, second};
  EXPECT_EQ(observations, (std::vector<Observation>{
                              {.signal = "root.fs_paths", .source = "access", .status = Status::kOk, .value = found},
                              {.signal = "root.fs_paths", .source = "stat", .status = Status::kOk, .value = found},
                          }));
}

TEST(Root, observePaths_whenNoPathExists_reportsEmptyListsThroughBothSources) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string missing = directory.path() + "/missing";
  const std::array<std::string_view, 1> paths = {missing};

  const std::vector<Observation> observations = observe_paths(paths);

  const std::vector<std::string> none;
  EXPECT_EQ(observations, (std::vector<Observation>{
                              {.signal = "root.fs_paths", .source = "access", .status = Status::kOk, .value = none},
                              {.signal = "root.fs_paths", .source = "stat", .status = Status::kOk, .value = none},
                          }));
}

/// A mount line that a root tool leaves, with one of the marks observe_mounts looks for.
class RootMountLine : public ::testing::TestWithParam<std::string_view> {};

TEST_P(RootMountLine, observeMounts_whenTheTableHasTheLine_reportsOnlyThatLine) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) + std::string(GetParam()) + "\n"));

  EXPECT_EQ(observe_mounts(table), mounts({std::string(GetParam())}));
}

INSTANTIATE_TEST_SUITE_P(
    Root, RootMountLine,
    ::testing::Values(
        "magisk /debug_ramdisk tmpfs rw,seclabel,relatime,mode=755 0 0", "tmpfs /dev/zygisk tmpfs rw,relatime 0 0",
        "/dev/block/dm-0 /sbin/.core/mirror/system ext4 ro,relatime 0 0", "tmpfs /debug_ramdisk tmpfs rw,relatime 0 0",
        "overlay /system/etc overlay ro,lowerdir=/data/adb/modules/hosts/system/etc 0 0",
        "KSU /vendor overlay ro,seclabel,relatime 0 0", "APatch /system/bin overlay ro,seclabel,relatime 0 0"));

TEST(Root, observeMounts_whenNoLineMentionsARootTool_reportsAnEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, kStockMounts));

  EXPECT_EQ(observe_mounts(table), mounts({}));
}

TEST(Root, observeMounts_whenTheTableIsEmpty_reportsAnEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, ""));

  EXPECT_EQ(observe_mounts(table), mounts({}));
}

TEST(Root, observeMounts_whenTheLastLineHasNoLineBreak_stillReportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) + "KSU /vendor overlay ro 0 0"));

  EXPECT_EQ(observe_mounts(table), mounts({"KSU /vendor overlay ro 0 0"}));
}

TEST(Root, observeMounts_whenMoreThan32LinesMatch_reportsTheFirst32) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  std::string content;
  std::vector<std::string> first;
  for (int index = 0; index < 40; ++index) {
    const std::string line = "magisk /mnt/" + std::to_string(index) + " tmpfs rw 0 0";
    content += line + "\n";
    if (index < 32) {
      first.push_back(line);
    }
  }
  ASSERT_TRUE(write_file(table, content));

  EXPECT_EQ(observe_mounts(table), mounts(first));
}

TEST(Root, observeMounts_whenTheTableIsExactly1MiB_readsItWhole) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  const std::string last = "magisk /debug_ramdisk tmpfs rw 0 0";
  const std::string content = std::string(kMountsLimit - last.size() - 1, 'a') + "\n" + last;
  ASSERT_EQ(content.size(), kMountsLimit);
  ASSERT_TRUE(write_file(table, content));

  EXPECT_EQ(observe_mounts(table), mounts({last}));
}

TEST(Root, observeMounts_whenTheTableIsLargerThan1MiB_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  const std::string last = "magisk /debug_ramdisk tmpfs rw 0 0";
  ASSERT_TRUE(write_file(table, std::string(kMountsLimit - last.size(), 'a') + "\n" + last));

  EXPECT_EQ(observe_mounts(table), unreadable_mounts());
}

TEST(Root, observeMounts_whenTheTableIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_mounts(directory.path() + "/missing"), unreadable_mounts());
}

TEST(Root, observeMounts_whenTheTableCantBeRead_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_mounts(directory.path()), unreadable_mounts());
}

TEST(Root, observeMounts_whenKsuOrAPatchIsNotTheSource_ignoresTheLine) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) +
                                    "overlay /mnt/2O5KSUC6DP5XA2ZYN overlay ro,lowerdir=/mnt/l/QKSU 0 0\n"
                                    "tmpfs /mnt/APatch tmpfs ro,relatime 0 0\n"
                                    "KSUX /mnt overlay ro 0 0\n"));

  EXPECT_EQ(observe_mounts(table), mounts({}));
}

/// A mount line that mounts a system folder writable.
class RootWritableMountLine : public ::testing::TestWithParam<std::string_view> {};

TEST_P(RootWritableMountLine, observeMounts_whenASystemFolderIsMountedWritable_reportsThatLine) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) + std::string(GetParam()) + "\n"));

  EXPECT_EQ(observe_mounts(table), mounts({}, {std::string(GetParam())}));
}

INSTANTIATE_TEST_SUITE_P(Root, RootWritableMountLine,
                         ::testing::Values("/dev/block/dm-0 / ext4 rw,seclabel,relatime 0 0",
                                           "/dev/block/dm-0 /system ext4 rw,seclabel,relatime 0 0",
                                           "/dev/block/dm-0 /system/bin ext4 rw 0 0",
                                           "/dev/block/dm-0 /system/sbin ext4 rw 0 0",
                                           "/dev/block/dm-0 /system/xbin ext4 rw 0 0",
                                           "/dev/block/dm-1 /vendor ext4 seclabel,rw,relatime 0 0",
                                           "/dev/block/dm-1 /vendor/bin ext4 rw 0 0",
                                           "tmpfs /sbin tmpfs rw,seclabel,relatime,mode=755 0 0",
                                           "/dev/block/dm-0 /etc ext4 rw 0 0"));

TEST(Root, observeMounts_whenOnlyAFolderBelowASystemFolderIsWritable_ignoresIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) + "/dev/block/dm-5 /system/etc/hosts f2fs rw 0 0\n"));

  EXPECT_EQ(observe_mounts(table), mounts({}));
}

TEST(Root, observeMounts_whenAnOptionOnlyStartsWithRw_ignoresIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) + "/dev/block/dm-0 /system ext4 ro,rwx 0 0\n"));

  EXPECT_EQ(observe_mounts(table), mounts({}));
}

TEST(Root, observeMounts_whenALineHasFewerThanFourFields_ignoresItForWritableMounts) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) + "/dev/block/dm-0 /system ext4\nrw\n\n"));

  EXPECT_EQ(observe_mounts(table), mounts({}));
}

TEST(Root, observeMounts_whenARootToolMountsASystemFolderWritable_reportsTheLineInBothLists) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string table = directory.path() + "/mounts";
  const std::string line = "magisk /sbin tmpfs rw,seclabel,relatime,mode=755 0 0";
  ASSERT_TRUE(write_file(table, std::string(kStockMounts) + line + "\n"));

  EXPECT_EQ(observe_mounts(table), mounts({line}, {line}));
}

/// What a SELinux enforce file holds, and whether observe_selinux must read it as enforcing.
struct EnforceFile {
  /// The content of the file.
  std::string_view content;
  /// Whether it means SELinux enforces its policy.
  bool enforcing;
};

/// An enforce file that observe_selinux understands.
class RootEnforceFile : public ::testing::TestWithParam<EnforceFile> {};

TEST_P(RootEnforceFile, observeSelinux_whenTheFileHoldsADigit_reportsWhatItMeans) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string enforce = directory.path() + "/enforce";
  ASSERT_TRUE(write_file(enforce, GetParam().content));

  EXPECT_EQ(observe_selinux(enforce), selinux(GetParam().enforcing));
}

INSTANTIATE_TEST_SUITE_P(Root, RootEnforceFile,
                         ::testing::Values(EnforceFile{.content = "1", .enforcing = true},
                                           EnforceFile{.content = "1\n", .enforcing = true},
                                           EnforceFile{.content = "0", .enforcing = false},
                                           EnforceFile{.content = "0\n", .enforcing = false}));

/// An enforce file that holds something other than one digit and an optional line break.
class RootMalformedEnforceFile : public ::testing::TestWithParam<std::string_view> {};

TEST_P(RootMalformedEnforceFile, observeSelinux_whenTheFileHoldsAnythingElse_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string enforce = directory.path() + "/enforce";
  ASSERT_TRUE(write_file(enforce, GetParam()));

  EXPECT_EQ(
      observe_selinux(enforce),
      (Observation{.signal = "root.selinux_enforcing", .source = "selinuxfs", .status = Status::kError, .value = {}}));
}

INSTANTIATE_TEST_SUITE_P(Root, RootMalformedEnforceFile,
                         ::testing::Values("", "2", "10", " 1", "1\n\n", "enforcing", std::string_view("1\0", 2)));

TEST(Root, observeSelinux_whenTheFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(
      observe_selinux(directory.path() + "/missing"),
      (Observation{.signal = "root.selinux_enforcing", .source = "selinuxfs", .status = Status::kError, .value = {}}));
}

TEST(Root, observeSelinux_whenTheFileIsLargerThanTheLimit_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string enforce = directory.path() + "/enforce";
  ASSERT_TRUE(write_file(enforce, "1" + std::string(64, '\n')));

  EXPECT_EQ(
      observe_selinux(enforce),
      (Observation{.signal = "root.selinux_enforcing", .source = "selinuxfs", .status = Status::kError, .value = {}}));
}

TEST(Root, observeBuildProps_whenEveryPropertyIsSet_reportsEachAsNameEqualsValueInOrder) {
  EXPECT_EQ(observe_build_props(read_unlocked_phone), build_props({
                                                          "ro.debuggable=0",
                                                          "ro.secure=1",
                                                          "ro.build.type=user",
                                                          "ro.build.tags=release-keys",
                                                          "ro.boot.verifiedbootstate=orange",
                                                          "ro.boot.vbmeta.device_state=unlocked",
                                                          "ro.boot.flash.locked=0",
                                                      }));
}

TEST(Root, observeBuildProps_whenSomePropertiesAreUnset_leavesThemOut) {
  EXPECT_EQ(observe_build_props(read_emulator), build_props({
                                                    "ro.debuggable=0",
                                                    "ro.secure=1",
                                                    "ro.build.type=user",
                                                    "ro.build.tags=release-keys",
                                                }));
}

TEST(Root, observeBuildProps_whenAPropertyIsSetToAnEmptyValue_reportsItWithTheEmptyValue) {
  EXPECT_EQ(observe_build_props(read_empty), build_props({
                                                 "ro.debuggable=",
                                                 "ro.secure=",
                                                 "ro.build.type=",
                                                 "ro.build.tags=",
                                                 "ro.boot.verifiedbootstate=",
                                                 "ro.boot.vbmeta.device_state=",
                                                 "ro.boot.flash.locked=",
                                             }));
}

TEST(Root, observeBuildProps_whenNoPropertyIsSet_reportsAnEmptyList) {
  EXPECT_EQ(observe_build_props(read_nothing), build_props({}));
}

TEST(Root, root_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(
      root(),
      (std::vector<Observation>{
          {.signal = "root.fs_paths", .source = "access", .status = Status::kUnsupported, .value = {}},
          {.signal = "root.fs_paths", .source = "stat", .status = Status::kUnsupported, .value = {}},
          {.signal = "root.mounts", .source = "proc_mounts", .status = Status::kUnsupported, .value = {}},
          {.signal = "root.rw_mounts", .source = "proc_mounts", .status = Status::kUnsupported, .value = {}},
          {.signal = "root.selinux_enforcing", .source = "selinuxfs", .status = Status::kUnsupported, .value = {}},
          {.signal = "root.build_props", .source = "system_property", .status = Status::kUnsupported, .value = {}},
      }));
}

}  // namespace
}  // namespace rasp::android::checks
