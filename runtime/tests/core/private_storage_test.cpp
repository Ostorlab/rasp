/// Adversarial native filesystem tests of the shared production private storage path.
#include "rasp/private_storage.h"

#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <optional>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

#include "rasp/posix/private_storage.h"
#include "support/files.h"

namespace rasp {
namespace {
TEST(PrivateStorage, acquire_whenPrivateDirectoryExists_returnsOwnedDescriptorAndStableIdentity) {
  const test_support::TemporaryDirectory directory;
  auto first = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(first.has_value());
  EXPECT_GE(first->native_handle(), 0);
  const std::string install_id(first->install_id());
  EXPECT_EQ(install_id.size(), 36);
  EXPECT_NE(install_id, "00000000-0000-0000-0000-000000000000");
  auto second = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(second->install_id(), install_id);
  EXPECT_TRUE(first->close().has_value());
  EXPECT_EQ(first->native_handle(), -1);
}
}  // namespace
}  // namespace rasp

namespace rasp {
namespace {
constexpr std::string_view kKeptIdentity = "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b";

TEST(PrivateStorage, acquire_whenLegacyIdentityIsValid_preservesAndHardensOnlyThatOwnedFile) {
  const test_support::TemporaryDirectory directory;
  const std::string path = directory.path() + "/rasp_install_id";
  ASSERT_TRUE(test_support::write_file(path, kKeptIdentity));
  ASSERT_EQ(chmod(path.c_str(), 0644), 0);
  auto storage = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(storage.has_value());
  EXPECT_EQ(storage->install_id(), kKeptIdentity);
  struct stat info{};
  ASSERT_EQ(stat(path.c_str(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777U, 0600);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX API with explicit bounded arguments.
  EXPECT_NE(static_cast<unsigned int>(fcntl(storage->native_handle(), F_GETFD)) & FD_CLOEXEC, 0);
  ASSERT_EQ(fstat(storage->native_handle(), &info), 0);
  EXPECT_EQ(info.st_mode & 0777U, 0700);
}

TEST(PrivateStorage, acquire_whenIdentityIsCorrupt_doesNotRotateOrTruncate) {
  for (const std::string& value : {
           std::string(),
           std::string("invalid"),
           std::string(4097, 'a'),
           std::string("00000000-0000-0000-0000-000000000000"),
           std::string("0F8E5B8E-6C1A-4B7E-9D3A-2A4C5E6F7A8B"),
           std::string(kKeptIdentity) + "\n",
       }) {
    const test_support::TemporaryDirectory directory;
    const std::string path = directory.path() + "/rasp_install_id";
    ASSERT_TRUE(test_support::write_file(path, value));
    const auto storage = posix::acquire_private_storage_at(directory.path());
    ASSERT_FALSE(storage.has_value());
    EXPECT_EQ(storage.error(), StorageError::kInvalidIdentity);
    EXPECT_EQ(test_support::read_file(path), value);
  }
}

/// Creates one real hostile filesystem object at the syscall boundary.
[[nodiscard]] int create_unsafe_object(int kind, const std::string& target, const std::string& path) {
  switch (kind) {
    case 0:
      return symlink(target.c_str(), path.c_str());
    case 1:
      return mkfifo(path.c_str(), 0600);
    case 2:
      return mkdir(path.c_str(), 0700);
    default:
      return link(target.c_str(), path.c_str());
  }
}

/// Exercises one unsafe object without hiding assertion failures in nested fixture loops.
void check_unsafe_file(std::string_view name, int kind) {
  const test_support::TemporaryDirectory directory;
  const test_support::TemporaryDirectory outside;
  const std::string target = outside.path() + "/target";
  const std::string path = directory.path() + "/" + std::string(name);
  ASSERT_TRUE(test_support::write_file(target, kKeptIdentity));
  ASSERT_EQ(create_unsafe_object(kind, target, path), 0);
  const auto storage = posix::acquire_private_storage_at(directory.path());
  EXPECT_FALSE(storage.has_value()) << name << " kind=" << kind;
  EXPECT_EQ(test_support::read_file(target), kKeptIdentity);
  struct stat info{};
  EXPECT_EQ(lstat(path.c_str(), &info), 0);
}

TEST(PrivateStorage, acquire_whenFileIsSymlinkFifoDirectoryOrHardlink_rejectsWithoutBlockingOrChangingTarget) {
  for (const std::string_view name : {"rasp_install_id", "rasp_install_id.lock", "rasp_install_id.private.tmp"}) {
    for (int kind = 0; kind < 4; ++kind) {
      check_unsafe_file(name, kind);
    }
  }
}

TEST(PrivateStorage, acquire_whenChildOrPathIsSymlinkOrTraverses_rejects) {
  const test_support::TemporaryDirectory directory;
  const test_support::TemporaryDirectory outside;
  ASSERT_EQ(symlink(outside.path().c_str(), (directory.path() + "/rasp_private").c_str()), 0);
  EXPECT_FALSE(posix::acquire_private_storage_at(directory.path()).has_value());
  EXPECT_FALSE(posix::acquire_private_storage_at(directory.path() + "/../" + outside.path()).has_value());
  EXPECT_FALSE(posix::acquire_private_storage_at("relative").has_value());
  EXPECT_FALSE(posix::acquire_private_storage_at(directory.path() + "/").has_value());
  EXPECT_FALSE(posix::acquire_private_storage_at(std::string(4096, 'a')).has_value());
  EXPECT_FALSE(posix::acquire_private_storage_at(directory.path() + std::string("\0suffix", 7)).has_value());
}

/// Checks one invalid parent permission mode and restores fixture cleanup permissions.
void check_directory_mode(mode_t mode) {
  const test_support::TemporaryDirectory directory;
  ASSERT_EQ(chmod(directory.path().c_str(), mode), 0);
  EXPECT_FALSE(posix::acquire_private_storage_at(directory.path()).has_value());
  ASSERT_EQ(chmod(directory.path().c_str(), 0700), 0);
}

TEST(PrivateStorage, acquire_whenDirectoryOrIdentityPermissionsAreUnsafe_rejects) {
  for (const mode_t mode : {static_cast<mode_t>(0777), static_cast<mode_t>(0555), static_cast<mode_t>(0500)}) {
    check_directory_mode(mode);
  }
  const test_support::TemporaryDirectory directory;
  const std::string identity = directory.path() + "/rasp_install_id";
  ASSERT_TRUE(test_support::write_file(identity, kKeptIdentity));
  ASSERT_EQ(chmod(identity.c_str(), 0666), 0);
  EXPECT_FALSE(posix::acquire_private_storage_at(directory.path()).has_value());
}

TEST(PrivateStorage, acquire_whenPlatformUsesAppGroupTraversal_acceptsAndCreatesOwnerOnlyChild) {
  const test_support::TemporaryDirectory directory;
  ASSERT_EQ(chmod(directory.path().c_str(), 0771), 0);
  const auto storage = posix::acquire_private_storage_at(directory.path());
  EXPECT_TRUE(storage.has_value());
}

TEST(PrivateStorage, acquire_whenBackupPreparationFails_createsNoIdentityOrQueuePayload) {
  const test_support::TemporaryDirectory directory;
  const auto storage = posix::acquire_private_storage_at(directory.path(), [](std::string_view) { return false; });
  ASSERT_FALSE(storage.has_value());
  EXPECT_EQ(storage.error(), StorageError::kBackupExclusionFailed);
  EXPECT_EQ(access((directory.path() + "/rasp_install_id").c_str(), F_OK), -1);
  EXPECT_EQ(access((directory.path() + "/rasp_install_id.lock").c_str(), F_OK), -1);
  const auto retry = posix::acquire_private_storage_at(directory.path(), [](std::string_view) { return true; });
  EXPECT_TRUE(retry.has_value());
}

TEST(PrivateStorage, acquire_whenLockIsHeld_reportsBusyThenSucceedsWithoutThreadsOrIdentityChange) {
  const test_support::TemporaryDirectory directory;
  const std::string lock_path = directory.path() + "/rasp_install_id.lock";
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX API with explicit bounded arguments.
  const int lock_fd = open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  ASSERT_GE(lock_fd, 0);
  ASSERT_EQ(flock(lock_fd, LOCK_EX | LOCK_NB), 0);
  const auto blocked = posix::acquire_private_storage_at(directory.path());
  ASSERT_FALSE(blocked.has_value());
  EXPECT_EQ(blocked.error(), StorageError::kBusy);
  ASSERT_EQ(close(lock_fd), 0);
  EXPECT_TRUE(posix::acquire_private_storage_at(directory.path()).has_value());
}

TEST(PrivateStorage, acquire_whenCrashLeftOwnedTemporary_discardsOnlyStaleTemporaryAndPublishesWholeIdentity) {
  const test_support::TemporaryDirectory directory;
  const std::string temporary = directory.path() + "/rasp_install_id.private.tmp";
  ASSERT_TRUE(test_support::write_file(temporary, "partial"));
  auto storage = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(storage.has_value());
  EXPECT_EQ(test_support::read_file(directory.path() + "/rasp_install_id"), storage->install_id());
  EXPECT_EQ(access(temporary.c_str(), F_OK), -1);
  const std::string identity(storage->install_id());
  ASSERT_TRUE(storage->close().has_value());
  auto restarted = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(restarted.has_value());
  EXPECT_EQ(restarted->install_id(), identity);
}

TEST(PrivateStorage, move_whenCapabilityIsTransferred_transfersOwnershipAndCheckedCloseIsIdempotent) {
  const test_support::TemporaryDirectory directory;
  auto first = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(first.has_value());
  const int descriptor = first->native_handle();
  PrivateStorage second(std::move(*first));
  EXPECT_EQ(first->native_handle(), -1);
  EXPECT_EQ(second.native_handle(), descriptor);
  EXPECT_TRUE(second.close().has_value());
  EXPECT_TRUE(second.close().has_value());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX API with explicit bounded arguments.
  EXPECT_EQ(fcntl(descriptor, F_GETFD), -1);
}
}  // namespace
}  // namespace rasp

namespace rasp {
namespace {
TEST(PrivateStorage, acquire_whenAppControlsIntermediateSymlink_rejectsCanonicalizedDirectory) {
  const test_support::TemporaryDirectory directory;
  const test_support::TemporaryDirectory outside;
  ASSERT_EQ(mkdir((outside.path() + "/owned").c_str(), 0700), 0);
  ASSERT_EQ(symlink(outside.path().c_str(), (directory.path() + "/mutable").c_str()), 0);
  const auto result = posix::open_platform_directory(
      {.absolute = directory.path() + "/mutable/owned", .canonical = outside.path() + "/owned"});
  EXPECT_FALSE(result.has_value());
}

TEST(PrivateStorage, acquire_whenAncestorIsExecuteOnly_pinsDirectoryWithoutListingAncestor) {
  const test_support::TemporaryDirectory directory;
  const std::string child = directory.path() + "/private";
  ASSERT_EQ(mkdir(child.c_str(), 0700), 0);
  ASSERT_EQ(chmod(directory.path().c_str(), 0111), 0);
  const auto result = posix::acquire_private_storage_at(child);
  ASSERT_EQ(chmod(directory.path().c_str(), 0700), 0);
  EXPECT_TRUE(result.has_value());
}

TEST(PrivateStorage, acquire_whenRealPrivilegedOsAncestorAliasExists_acceptsOnlySameCanonicalInode) {
#ifdef __linux__
  const std::string canonical_base = "/run/user/" + std::to_string(geteuid());
  if (access(canonical_base.c_str(), W_OK) != 0) {
    GTEST_SKIP() << "no private /run/user fixture location";
  }
  std::string pattern = canonical_base + "/rasp-alias-XXXXXX";
  ASSERT_NE(mkdtemp(pattern.data()), nullptr);
  const std::string alias = "/var/run/user/" + std::to_string(geteuid()) + pattern.substr(canonical_base.size());
  const auto descriptor = posix::open_platform_directory({.absolute = alias, .canonical = pattern});
  ASSERT_TRUE(descriptor.has_value());
  EXPECT_EQ(close(*descriptor), 0);
  const test_support::TemporaryDirectory different;
  EXPECT_FALSE(posix::open_platform_directory({.absolute = alias, .canonical = different.path()}).has_value());
  EXPECT_EQ(rmdir(pattern.c_str()), 0);
#else
  const test_support::TemporaryDirectory directory;
  const auto descriptor = posix::open_platform_directory({.absolute = directory.path(), .canonical = directory.path()});
  ASSERT_TRUE(descriptor.has_value());
  EXPECT_EQ(close(*descriptor), 0);
#endif
}
}  // namespace
}  // namespace rasp

namespace rasp {
namespace {
/// Spawns an actual native executable with an empty environment, with all filesystem work after exec, never in fork.
[[nodiscard]] std::optional<pid_t> spawn_probe(const std::string& root, std::pair<std::string, std::string> output) {
  std::string executable = RASP_STORAGE_PROBE;
  std::string root_copy = root;
  std::string name_copy = std::move(output.first);
  std::string identity_copy = std::move(output.second);
  std::array<char*, 5> arguments{executable.data(), root_copy.data(), name_copy.data(), identity_copy.data(), nullptr};
  std::array<char*, 1> environment{nullptr};
  pid_t process = -1;
  if (posix_spawn(&process, executable.c_str(), nullptr, nullptr, arguments.data(), environment.data()) != 0) {
    return std::nullopt;
  }
  return process;
}

/// Checks process success outside a nested macro loop.
void wait_probe(pid_t process) {
  int status = -1;
  ASSERT_EQ(waitpid(process, &status, 0), process);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(PrivateStorage, acquire_whenExecProcessesRaceAndRestart_keepSameDurableIdentityAndQueueOwner) {
  const test_support::TemporaryDirectory directory;
  const auto first = spawn_probe(directory.path(), {"first", ""});
  const auto second = spawn_probe(directory.path(), {"second", ""});
  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  wait_probe(*first);
  wait_probe(*second);
  const auto identity = test_support::read_file(directory.path() + "/rasp_private/first");
  ASSERT_TRUE(identity.has_value());
  EXPECT_EQ(test_support::read_file(directory.path() + "/rasp_private/second"), identity);
  EXPECT_EQ(test_support::read_file(directory.path() + "/rasp_install_id"), identity);
  const auto restarted = spawn_probe(directory.path(), {"restarted", *identity});
  ASSERT_TRUE(restarted.has_value());
  wait_probe(*restarted);
  EXPECT_EQ(test_support::read_file(directory.path() + "/rasp_private/restarted"), identity);
}
}  // namespace
}  // namespace rasp

namespace rasp {
namespace {
TEST(PrivateStorage, acquire_whenPreparationChangesChildPermissions_rejectsBeforeExposingDescriptor) {
  const test_support::TemporaryDirectory directory;
  const auto result = posix::acquire_private_storage_at(
      directory.path(), [](std::string_view path) { return chmod(std::string(path).c_str(), 0755) == 0; });
  EXPECT_FALSE(result.has_value());
}
}  // namespace
}  // namespace rasp
