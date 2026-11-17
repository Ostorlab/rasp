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
  const std::filesystem::path path = dir.path / "copy_of_status";
  write_file(path, "Name:\tapp\nTracerPid:\t0\n");

  EXPECT_FALSE(read_proc_file(path.string(), kLimit).has_value());
}

TEST(RawFile, readProcFile_whenTheFileIsLongerThanTheLimit_refusesIt) {
  EXPECT_FALSE(read_proc_file("/proc/self/status", 8).has_value());
}

TEST(RawFile, readProcFile_whenTheFileIsMissing_refusesIt) {
  EXPECT_FALSE(read_proc_file("/proc/self/no_such_file", kLimit).has_value());
}

}  // namespace
}  // namespace rasp::util
