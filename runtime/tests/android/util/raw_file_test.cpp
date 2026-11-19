/// Tests for read_proc_file, which reads a kernel-generated file through direct system calls.

#include "util/raw_file.h"

#include <cstddef>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>

#include "support/files.h"

namespace rasp::util {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// The size limit the device's sensors read with, 64 KiB.
constexpr std::size_t kLimit = std::size_t{64} << 10U;

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

}  // namespace
}  // namespace rasp::util
