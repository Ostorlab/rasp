/// Production mount grammar, namespace identity and bounded descriptor tests.
#include "checks/root_namespace.h"

#include <cerrno>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

#ifdef RASP_TEST_WRAP_FSTAT
namespace {
/// Faults stay on the calling fixture thread and never reach production binaries.
[[nodiscard]] int& metadata_fault() {
  static thread_local int value = 0;
  return value;
}
/// Tracks descriptor metadata calls within one read.
[[nodiscard]] int& metadata_reads() {
  static thread_local int value = 0;
  return value;
}
}  // namespace
/// Links the real filesystem boundary under GNU ld's documented wrapping contract.
extern "C" int real_stat(int descriptor, struct stat* metadata) asm("__real_fstat");
/// Simulates a regular file changing/disappearing after the production reader opened it.
extern "C" int wrap_stat(int descriptor, struct stat* metadata) asm("__wrap_fstat");
extern "C" int wrap_stat(int descriptor, struct stat* metadata) {
  const int result = real_stat(descriptor, metadata);
  if (metadata_fault() == 0 || result != 0 || ++metadata_reads() != 2) {
    return result;
  }
  if (metadata_fault() == 1) {
    ++metadata->st_size;
  }
  if (metadata_fault() == 2) {
    ++metadata->st_ino;
  }
  if (metadata_fault() == 3) {
    ++metadata->st_mtim.tv_nsec;
  }
  if (metadata_fault() == 4) {
    errno = EIO;
    return -1;
  }
  return result;
}
#endif

namespace rasp::android::checks {
namespace {
/// Stock system and benign container mounts, including kernel octal escapes and propagation fields.
constexpr std::string_view kStock =
    "21 1 8:1 / / ro,relatime shared:1 - ext4 /dev/block/dm-0 ro,seclabel\n"
    "22 21 0:2 / /data/my\\040folder rw,nosuid master:2 propagate_from:3 - overlay overlay rw,lowerdir=/a\\134b\n";
TEST(RootNamespace, observeMountinfo_whenStockContainerOverlay_reportsContextWithoutVerdict) {
  EXPECT_EQ(observe_mountinfo(kStock),
            observed("root.mountinfo_context_v1", "proc_self_mountinfo",
                     std::vector<std::string>{"mounts=2", "overlay=1", "shared=1", "master=1", "root_rw=false"}));
}
TEST(RootNamespace, observeMountinfo_whenNamespaceFilesystemUsesSyntheticRoot_reportsBenignContext) {
  EXPECT_EQ(
      observe_mountinfo(std::string(kStock) + "23 21 0:4 net:[4026533004] /run/netns/test rw - nsfs nsfs rw\n").status,
      Status::kOk);
}
TEST(RootNamespace, observeMountinfo_whenMalformedOrOverLimit_reportsUnknown) {
  for (const std::string& text : std::vector<std::string>{
           "",
           "1 2 0:1 / / rw - tmpfs tmpfs rw",
           "0 2 0:1 / / rw - tmpfs tmpfs rw\n",
           "1 2 0:x / / rw - tmpfs tmpfs rw\n",
           "1 2 0:1 relative / rw - tmpfs tmpfs rw\n",
           "1 2 0:1 / /a\\999 rw - tmpfs tmpfs rw\n",
           "1 2 0:1 / / rw shared:x - tmpfs tmpfs rw\n",
           "1 2 0:1 / / rw - tmpfs tmpfs rw extra\n",
           std::string(1048577, 'x'),
       }) {
    EXPECT_EQ(observe_mountinfo(text).status, Status::kError) << text.substr(0, 120);
  }
  std::string rows;
  for (int index = 0; index < 4097; ++index) {
    rows += "1 2 0:1 / / rw - tmpfs tmpfs rw\n";
  }
  EXPECT_EQ(observe_mountinfo(rows).status, Status::kError);
}
TEST(RootNamespace, observeMountinfoFile_whenRegularThenDisappears_reportsSuccessThenError) {
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/table";
  ASSERT_TRUE(test_support::write_file(path, kStock));
  EXPECT_EQ(observe_mountinfo_file(path), observe_mountinfo(kStock));
  ASSERT_EQ(unlink(path.c_str()), 0);
  EXPECT_EQ(observe_mountinfo_file(path).status, Status::kError);
}
TEST(RootNamespace, observeMountinfoFile_whenFifoSymlinkDirectory_reportsErrorPromptly) {
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/table";
  ASSERT_TRUE(test_support::write_file(path, kStock));
  ASSERT_EQ(symlink(path.c_str(), (path + ".link").c_str()), 0);
  ASSERT_TRUE(test_support::make_fifo(path + ".fifo"));
  for (const auto& candidate : {path + ".link", path + ".fifo", path + ".missing", directory.path()}) {
    EXPECT_EQ(observe_mountinfo_file(candidate).status, Status::kError);
  }
}
TEST(RootNamespace, observeMountinfoFile_whenAccessDenied_reportsUnknown) {
  if (geteuid() == 0) {
    GTEST_SKIP() << "root bypasses ordinary file permissions";
  }
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/table";
  ASSERT_TRUE(test_support::write_file(path, kStock));
  ASSERT_EQ(chmod(path.c_str(), 0), 0);
  EXPECT_EQ(observe_mountinfo_file(path).status, Status::kError);
}
#ifdef RASP_TEST_WRAP_FSTAT
TEST(RootNamespace, observeMountinfoFile_whenDescriptorMetadataChangesOrFails_reportsUnknown) {
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/table";
  ASSERT_TRUE(test_support::write_file(path, kStock));
  for (int fault = 1; fault <= 4; ++fault) {
    metadata_fault() = fault;
    metadata_reads() = 0;
    const auto result = observe_mountinfo_file(path);
    metadata_fault() = 0;
    EXPECT_EQ(result.status, Status::kError);
  }
}
#endif
TEST(RootNamespace, observeMountNamespace_whenLinkValid_reportsOnlyLocalIdentity) {
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/ns";
  ASSERT_EQ(symlink("mnt:[4026531840]", path.c_str()), 0);
  EXPECT_EQ(observe_mount_namespace(path),
            observed("root.mount_namespace_v1", "proc_self_ns_mnt", std::string("mnt:[4026531840]")));
  ASSERT_EQ(unlink(path.c_str()), 0);
  ASSERT_EQ(symlink("pid:[1]", path.c_str()), 0);
  EXPECT_EQ(observe_mount_namespace(path).status, Status::kError);
}
}  // namespace
}  // namespace rasp::android::checks
