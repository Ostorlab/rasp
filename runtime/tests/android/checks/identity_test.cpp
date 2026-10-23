/// Tests for the Android app-identity self-check: the package-name probe that reads the process's command line.

#include "checks/identity.h"

#include <gtest/gtest.h>
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

/// The id.package observation that reports `package`.
[[nodiscard]] Observation package(std::string package_name) {
  return {.signal = "id.package", .source = "proc_cmdline", .status = Status::kOk, .value = std::move(package_name)};
}

/// The id.package observation that failed.
[[nodiscard]] Observation unreadable_package() {
  return {.signal = "id.package", .source = "proc_cmdline", .status = Status::kError, .value = {}};
}

/// Writes `content` to a cmdline file in `directory` and returns its path.
[[nodiscard]] std::string write_cmdline(const TemporaryDirectory& directory, std::string_view content) {
  const std::string path = directory.path() + "/cmdline";
  return write_file(path, content) ? path : std::string();
}

TEST(Identity, observePackage_whenTheCommandLineHoldsThePackage_reportsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  // A real cmdline is NUL-separated: the package name, then any arguments.
  const std::string path = write_cmdline(directory, std::string_view("co.ostorlab.app\0some-argument", 29));
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_package(path), package("co.ostorlab.app"));
}

TEST(Identity, observePackage_whenThereIsNoArgument_reportsTheWholeLine) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_cmdline(directory, "co.ostorlab.app");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_package(path), package("co.ostorlab.app"));
}

TEST(Identity, observePackage_whenRunningInANamedProcess_reportsThePackageWithoutTheSuffix) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  // A process declared with android:process has the name `<package>:<process>`; the package is the part before the
  // colon.
  const std::string path = write_cmdline(directory, "co.ostorlab.app:remote");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_package(path), package("co.ostorlab.app"));
}

TEST(Identity, observePackage_whenTheCommandLineIsEmpty_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_cmdline(directory, "");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_package(path), unreadable_package());
}

TEST(Identity, observePackage_whenTheFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_package(directory.path() + "/missing"), unreadable_package());
}

TEST(Identity, identity_whenOffAndroid_reportsTheCheckAsUnsupported) {
  EXPECT_EQ(identity(),
            (std::vector<Observation>{
                {.signal = "id.package", .source = "proc_cmdline", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::android::checks
