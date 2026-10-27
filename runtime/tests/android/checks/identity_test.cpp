/// Tests for the Android app-identity self-check: the package-name probe that reads the process's command line, the
/// user-id probe over the process's own uid, and the code-path probe over the runtime's own library load path.

#include "checks/identity.h"

#include <cstddef>
#include <cstdint>
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

/// The size limit observe_package reads the command line with, 64 KiB.
constexpr std::size_t kCmdlineLimit = std::size_t{64} << 10U;

/// The id.package observation that reports `package`.
[[nodiscard]] Observation package(std::string package_name) {
  return {.signal = "id.package", .source = "proc_cmdline", .status = Status::kOk, .value = std::move(package_name)};
}

/// The id.package observation that failed.
[[nodiscard]] Observation unreadable_package() {
  return {.signal = "id.package", .source = "proc_cmdline", .status = Status::kError, .value = {}};
}

/// The id.uid observation that reports `uid`.
[[nodiscard]] Observation uid(std::int64_t value) {
  return {.signal = "id.uid", .source = "getuid", .status = Status::kOk, .value = value};
}

/// The id.code_path observation that reports `path`.
[[nodiscard]] Observation code_path(std::string path) {
  return {.signal = "id.code_path", .source = "dladdr", .status = Status::kOk, .value = std::move(path)};
}

/// The id.code_path observation that failed.
[[nodiscard]] Observation unreadable_code_path() {
  return {.signal = "id.code_path", .source = "dladdr", .status = Status::kError, .value = {}};
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

TEST(Identity, observePackage_whenTheCommandLineIsExactly64KiB_readsThePackage) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  // The package is the first NUL-separated field; the rest of the file pads it out to exactly the limit.
  const std::string first = "co.ostorlab.app";
  const std::string content = first + '\0' + std::string(kCmdlineLimit - first.size() - 1, 'a');
  ASSERT_EQ(content.size(), kCmdlineLimit);
  const std::string path = write_cmdline(directory, content);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_package(path), package("co.ostorlab.app"));
}

TEST(Identity, observePackage_whenTheCommandLineIsLargerThan64KiB_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string first = "co.ostorlab.app";
  const std::string content = first + '\0' + std::string(kCmdlineLimit - first.size(), 'a');
  ASSERT_EQ(content.size(), kCmdlineLimit + 1);
  const std::string path = write_cmdline(directory, content);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_package(path), unreadable_package());
}

TEST(Identity, observePackage_whenThePathCantBeRead_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  // Reading a directory as a file fails.
  EXPECT_EQ(observe_package(directory.path()), unreadable_package());
}

TEST(Identity, observeUid_whenGivenAMainUserUid_reportsIt) {
  // A normal app on the main user has a uid in 10000-19999; the server reads user 0 from it.
  EXPECT_EQ(observe_uid(10123), uid(10123));
}

TEST(Identity, observeUid_whenGivenASecondaryUserUid_reportsIt) {
  // An app in user 1 (an OEM clone or a work profile) has a uid of 1 * 100000 + the app id; the server reads user 1.
  EXPECT_EQ(observe_uid(110123), uid(110123));
}

TEST(Identity, observeCodePath_whenGivenAnExtractedInstallPath_reportsIt) {
  // A genuine install with an extracted library loads it from a path that carries the app's own package name.
  const std::string path = "/data/app/~~abc==/co.ostorlab.app-xyz==/lib/arm64/librasp.so";

  EXPECT_EQ(observe_code_path(path), code_path(path));
}

TEST(Identity, observeCodePath_whenGivenAnApkEmbeddedPath_reportsItUnchanged) {
  // When AGP packages the library uncompressed (android:extractNativeLibs="false", the common modern default) it is
  // mapped straight from the APK, so dladdr gives a `base.apk!/` path. It still carries the app's package and is
  // reported as-is, not split.
  const std::string path = "/data/app/~~abc==/co.ostorlab.app-xyz==/base.apk!/lib/arm64/librasp.so";

  EXPECT_EQ(observe_code_path(path), code_path(path));
}

TEST(Identity, observeCodePath_whenGivenAVirtualizedPath_reportsIt) {
  // A virtualizer loads the library from the host app's directory, whose path carries the host's package instead.
  const std::string path = "/data/data/com.parallel.intl/virtual/data/user/0/co.ostorlab.app/lib/arm64/librasp.so";

  EXPECT_EQ(observe_code_path(path), code_path(path));
}

TEST(Identity, observeCodePath_whenGivenNoPath_reportsAnError) {
  EXPECT_EQ(observe_code_path(""), unreadable_code_path());
}

TEST(Identity, identity_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(identity(),
            (std::vector<Observation>{
                {.signal = "id.package", .source = "proc_cmdline", .status = Status::kUnsupported, .value = {}},
                {.signal = "id.uid", .source = "getuid", .status = Status::kUnsupported, .value = {}},
                {.signal = "id.code_path", .source = "dladdr", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::android::checks
