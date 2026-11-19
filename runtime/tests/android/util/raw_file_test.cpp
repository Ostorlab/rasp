/// Tests for read_proc_file and first_proc_line_matching, which read kernel-generated files through direct system
/// calls.

#include "util/raw_file.h"

#include <cstddef>
#include <fcntl.h>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>

#include "support/files.h"

namespace rasp::util {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// The size limit the device's sensors read with, 64 KiB.
constexpr std::size_t kLimit = std::size_t{64} << 10U;

TEST(RawFile, firstProcLineMatching_whenTheLineSitsInABigScan_findsItWithoutHoldingTheFile) {
  // The regression the streaming scan exists for: a map larger than the cap on a whole read, with the APK's line
  // early. A plain open stands in for the production opener so the scan runs over a regular file of known content.
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "big_map";
  std::string content = "7a0c00000000-7a0c00007000 r-xp 00000000 00:01 4913 /data/app~~x/base.apk\n";
  const std::string filler = std::string(200, 'x') + "\n";
  while (content.size() < (5U << 20U)) {
    content += filler;
  }
  ASSERT_TRUE(write_file(path.string(), content));

  const std::optional<std::string> line = first_proc_line_matching(
      path.string(), [](std::string_view l) { return l.contains("base.apk"); }, 8U << 20U,
      [](std::string_view p) { return static_cast<long>(open(std::string(p).c_str(), O_RDONLY)); });

  ASSERT_TRUE(line.has_value());
  EXPECT_TRUE(line->contains("/data/app~~x/base.apk"));
}

TEST(RawFile, firstProcLineMatching_whenNothingMatchesWithinTheCap_findsNothing) {
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "no_match";
  std::string content;
  const std::string filler = std::string(200, 'x') + "\n";
  while (content.size() < (2U << 20U)) {
    content += filler;
  }
  ASSERT_TRUE(write_file(path.string(), content));

  const std::optional<std::string> line = first_proc_line_matching(
      path.string(), [](std::string_view l) { return l.contains("base.apk"); }, 4096,
      [](std::string_view p) { return static_cast<long>(open(std::string(p).c_str(), O_RDONLY)); });

  EXPECT_FALSE(line.has_value());
}

TEST(RawFile, readProcFile_whenTheKernelGeneratesTheFile_readsItWhole) {
  const std::optional<std::string> status = read_proc_file("/proc/self/status", kLimit);

  ASSERT_TRUE(status.has_value());
  EXPECT_NE(status->find("Name:"), std::string::npos);
}

TEST(RawFile, readProcFile_whenTheFileHoldsStoredBytes_refusesIt) {
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "copy_of_status";
  ASSERT_TRUE(write_file(path.string(), "Name:\tapp\nTracerPid:\t0\n"));

  EXPECT_FALSE(read_proc_file(path.string(), kLimit).has_value());
}

TEST(RawFile, readProcFile_whenTheFileIsEmpty_refusesIt) {
  // The copy a size check can't tell apart: it claims no size, as the kernel's files do, and read as an empty scan it
  // would report a clean process. It lives on a regular filesystem, so the reader refuses it.
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "empty_copy";
  ASSERT_TRUE(write_file(path.string(), ""));

  EXPECT_FALSE(read_proc_file(path.string(), kLimit).has_value());
}

TEST(RawFile, readProcFile_whenTheFileLivesOnASysfsPath_readsIt) {
  // sysfs attributes report the page size as their st_size, so a size-based refusal would reject this genuine
  // kernel file; the filesystem check accepts it.
  const std::optional<std::string> online = read_proc_file("/sys/devices/system/cpu/online", kLimit);

  ASSERT_TRUE(online.has_value());
  EXPECT_FALSE(online->empty());
}

TEST(RawFile, readProcFile_whenTheFileIsLongerThanTheLimit_refusesIt) {
  EXPECT_FALSE(read_proc_file("/proc/self/status", 8).has_value());
}

TEST(RawFile, readProcFile_whenTheFileIsMissing_refusesIt) {
  EXPECT_FALSE(read_proc_file("/proc/self/no_such_file", kLimit).has_value());
}

/// The cap the apk locator scans the memory map with, 4 MiB.
constexpr std::size_t kMapsCap = std::size_t{4} << 20U;

TEST(RawFile, openProcFile_whenTheFileHoldsStoredBytes_refusesIt) {
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "copy_of_maps";
  ASSERT_TRUE(write_file(path.string(), "7a0c00000000-7a0c00007000 r-xp 00000000 00:01 4913 /data/app~~x/base.apk\n"));

  EXPECT_LT(open_proc_file(path.string()), 0);
}

TEST(RawFile, openProcFile_whenTheFileIsEmpty_refusesIt) {
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "empty_copy";
  ASSERT_TRUE(write_file(path.string(), ""));

  EXPECT_LT(open_proc_file(path.string()), 0);
}

TEST(RawFile, firstProcLineMatching_whenTheFileHoldsStoredBytes_findsNothing) {
  // The shipped opener: a forged copy of the map that names an APK must not steer the package the scan reports.
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "copy_of_maps";
  ASSERT_TRUE(write_file(path.string(), "7a0c00000000-7a0c00007000 r-xp 00000000 00:01 4913 /data/app~~x/base.apk\n"));

  const std::optional<std::string> line =
      first_proc_line_matching(path.string(), [](std::string_view l) { return l.contains("base.apk"); }, kMapsCap);

  EXPECT_FALSE(line.has_value());
}

TEST(RawFile, firstProcLineMatching_whenTheKernelGeneratesTheFile_findsTheLine) {
  const std::optional<std::string> line =
      first_proc_line_matching("/proc/self/maps", [](std::string_view l) { return l.contains("[stack]"); }, kMapsCap);

  ASSERT_TRUE(line.has_value());
  EXPECT_TRUE(line->contains("[stack]"));
}

TEST(RawFile, firstProcLineMatching_whenTheLastLineHasNoLineBreak_findsIt) {
  const TemporaryDirectory dir{};
  const std::filesystem::path path = std::filesystem::path(dir.path()) / "unterminated_map";
  ASSERT_TRUE(write_file(path.string(),
                         "7a0c00000000-7a0c00001000 r--p 00000000 00:01 12 /system/lib64/libc.so\n"
                         "7a0c00007000-7a0c0000e000 r-xp 00000000 00:01 4913 /data/app~~x/base.apk"));

  const std::optional<std::string> line = first_proc_line_matching(
      path.string(), [](std::string_view l) { return l.contains("base.apk"); }, kMapsCap,
      [](std::string_view p) { return static_cast<long>(open(std::string(p).c_str(), O_RDONLY)); });

  ASSERT_TRUE(line.has_value());
  EXPECT_TRUE(line->contains("/data/app~~x/base.apk"));
}

}  // namespace
}  // namespace rasp::util
