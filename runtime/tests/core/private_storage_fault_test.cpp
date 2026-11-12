/// Linux syscall-boundary failures injected into the actual shipped POSIX storage implementation.
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <gtest/gtest.h>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

#include "rasp/install_id.h"
#include "rasp/posix/private_storage.h"
#include "rasp/private_storage.h"
#include "support/files.h"

namespace {
/// One fault is active only on the test thread while executing the production provider.
enum class Fault : std::uint8_t {
  kNone,
  kRandom,
  kShortWrite,
  kRead,
  kFileSync,
  kPublishSync,
  kPublish,
  kCloseFile,
  kCloseLock,
  kForeignDirectory,
  kForeignFile,
  kForeignGroup,
  kChangedInode,
  kReadOnly,
  kLock,
  kBusy,
  kUnlink,
  kCompetingIdentity,
  kPublishedCleanup,
  kCloseDirectory,
};
/// Keeps fault injection thread-local without a process-lifetime global initializer.
Fault& active_fault() {
  thread_local Fault fault = Fault::kNone;
  return fault;
}
/// Counts actual lock syscalls while the test exercises legacy retries or a single provider attempt.
int& lock_calls() {
  thread_local int calls = 0;
  return calls;
}
/// Captures the actual competing inode before linkat returns EEXIST.
struct stat& competing_inode() {
  thread_local struct stat info{};
  return info;
}
}  // namespace
extern "C" {
int real_getentropy(void* bytes, std::size_t size) __asm__("__real_getentropy");
int wrap_getentropy(void* bytes, std::size_t size) __asm__("__wrap_getentropy");
ssize_t real_write(int descriptor, const void* bytes, std::size_t size) __asm__("__real_write");
ssize_t wrap_write(int descriptor, const void* bytes, std::size_t size) __asm__("__wrap_write");
ssize_t real_read(int descriptor, void* bytes, std::size_t size) __asm__("__real_read");
ssize_t wrap_read(int descriptor, void* bytes, std::size_t size) __asm__("__wrap_read");
int real_fsync(int descriptor) __asm__("__real_fsync");
int wrap_fsync(int descriptor) __asm__("__wrap_fsync");
int real_linkat(int source, const char* source_name, int target, const char* target_name,
                int flags) __asm__("__real_linkat");
int wrap_linkat(int source, const char* source_name, int target, const char* target_name,
                int flags) __asm__("__wrap_linkat");
int real_close(int descriptor) __asm__("__real_close");
int wrap_close(int descriptor) __asm__("__wrap_close");
int real_fstat(int descriptor, struct stat* info) __asm__("__real_fstat");
int wrap_fstat(int descriptor, struct stat* info) __asm__("__wrap_fstat");
int real_fstatat(int descriptor, const char* name, struct stat* info, int flags) __asm__("__real_fstatat");
int wrap_fstatat(int descriptor, const char* name, struct stat* info, int flags) __asm__("__wrap_fstatat");
int real_flock(int descriptor, int operation) __asm__("__real_flock");
int wrap_flock(int descriptor, int operation) __asm__("__wrap_flock");
int real_unlinkat(int descriptor, const char* name, int flags) __asm__("__real_unlinkat");
int wrap_unlinkat(int descriptor, const char* name, int flags) __asm__("__wrap_unlinkat");

/// Fails the OS entropy source without replacing production UUID code.
int wrap_getentropy(void* bytes, std::size_t size) {
  if (active_fault() == Fault::kRandom) {
    errno = EIO;
    return -1;
  }
  return real_getentropy(bytes, size);
}
/// Makes a real partial identity write, or simulates a read-only mount at the write boundary.
ssize_t wrap_write(int descriptor, const void* bytes, std::size_t size) {
  struct stat info{};
  if (real_fstat(descriptor, &info) == 0 && S_ISREG(info.st_mode)) {
    if (active_fault() == Fault::kShortWrite && size > 1) {
      return real_write(descriptor, bytes, size - 1);
    }
    if (active_fault() == Fault::kReadOnly) {
      errno = EROFS;
      return -1;
    }
  }
  return real_write(descriptor, bytes, size);
}
/// Fails reading an existing identity.
ssize_t wrap_read(int descriptor, void* bytes, std::size_t size) {
  if (active_fault() == Fault::kRead) {
    errno = EIO;
    return -1;
  }
  return real_read(descriptor, bytes, size);
}
/// Separately fails file durability and post-publication directory durability.
int wrap_fsync(int descriptor) {
  struct stat info{};
  if (real_fstat(descriptor, &info) == 0) {
    if (active_fault() == Fault::kFileSync && S_ISREG(info.st_mode)) {
      errno = EIO;
      return -1;
    }
    if (active_fault() == Fault::kPublishSync && S_ISDIR(info.st_mode) &&
        real_fstatat(descriptor, "rasp_install_id", &info, AT_SYMLINK_NOFOLLOW) == 0) {
      errno = EIO;
      return -1;
    }
  }
  return real_fsync(descriptor);
}
/// Fails atomic publication without faking any filesystem validation.
int wrap_linkat(int source, const char* source_name, int target, const char* target_name, int flags) {
  if (active_fault() == Fault::kCompetingIdentity) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): creates the competing inode at the actual atomic publish boundary.
    const int competitor = openat(target, target_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    constexpr std::string_view kCompetitor = "00000000-1111-4222-8333-444444444444";
    if (competitor < 0) {
      return -1;
    }
    const bool written = real_write(competitor, kCompetitor.data(), kCompetitor.size()) == 36;
    const bool synced = real_fsync(competitor) == 0;
    static_cast<void>(real_fstat(competitor, &competing_inode()));
    const bool closed = real_close(competitor) == 0;
    if (!written || !synced || !closed) {
      errno = EIO;
      return -1;
    }
  }
  if (active_fault() == Fault::kPublish) {
    errno = EIO;
    return -1;
  }
  return real_linkat(source, source_name, target, target_name, flags);
}
/// Models a descriptor that was closed despite a reported error, checking that production never retries close.
int wrap_close(int descriptor) {
  struct stat info{};
  const bool fail = real_fstat(descriptor, &info) == 0 &&
                    ((S_ISDIR(info.st_mode) && active_fault() == Fault::kCloseDirectory) ||
                     (S_ISREG(info.st_mode) && ((active_fault() == Fault::kCloseFile && info.st_size == 36) ||
                                                (active_fault() == Fault::kCloseLock && info.st_size == 0))));
  const int result = real_close(descriptor);
  if (fail) {
    errno = EIO;
    return -1;
  }
  return result;
}
/// Models foreign directory/file ownership even when CI cannot create foreign-UID fixtures.
int wrap_fstat(int descriptor, struct stat* info) {
  const int result = real_fstat(descriptor, info);
  if (result == 0 && ((active_fault() == Fault::kForeignDirectory && S_ISDIR(info->st_mode)) ||
                      (active_fault() == Fault::kForeignFile && S_ISREG(info->st_mode)))) {
    ++info->st_uid;
  }
  if (result == 0 && active_fault() == Fault::kForeignGroup && S_ISDIR(info->st_mode)) {
    ++info->st_gid;
    info->st_mode |= 0020U;
  }
  return result;
}
/// Models replacement between open and path validation.
int wrap_fstatat(int descriptor, const char* name, struct stat* info, int flags) {
  const int result = real_fstatat(descriptor, name, info, flags);
  if (result == 0 && active_fault() == Fault::kChangedInode) {
    ++info->st_ino;
  }
  return result;
}
/// Makes interrupted/failed locking explicit rather than treating it as ownership.
int wrap_flock(int descriptor, int operation) {
  ++lock_calls();
  if (active_fault() == Fault::kBusy) {
    errno = EWOULDBLOCK;
    return -1;
  }
  if (active_fault() == Fault::kLock) {
    errno = EINTR;
    return -1;
  }
  return real_flock(descriptor, operation);
}
/// Leaves an owned crash temporary in place when cleanup cannot be completed.
int wrap_unlinkat(int descriptor, const char* name, int flags) {
  struct stat info{};
  if (active_fault() == Fault::kPublishedCleanup &&
      real_fstatat(descriptor, "rasp_install_id", &info, AT_SYMLINK_NOFOLLOW) == 0) {
    errno = EIO;
    return -1;
  }
  if (active_fault() == Fault::kUnlink) {
    errno = EIO;
    return -1;
  }
  return real_unlinkat(descriptor, name, flags);
}
}

namespace rasp {
namespace {
/// Runs exactly one provider call with a thread-local syscall fault and always clears it before test diagnostics.
[[nodiscard]] std::expected<PrivateStorage, StorageError> acquire_fault(std::string_view path, Fault fault) {
  active_fault() = fault;
  auto result = posix::acquire_private_storage_at(path);
  active_fault() = Fault::kNone;
  return result;
}

/// The Linux process's actual open descriptor count, including this temporary enumeration handle.
[[nodiscard]] std::ptrdiff_t descriptor_count() {
  return std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator());
}

TEST(PrivateStorageFault, legacy_whenBusyBudgetExpires_closesEveryAttemptAndParent) {
  const test_support::TemporaryDirectory directory;
  const auto before = descriptor_count();
  lock_calls() = 0;
  active_fault() = Fault::kBusy;
  const auto result = load_or_create_install_id(directory.path());
  active_fault() = Fault::kNone;
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(lock_calls(), 11);
  EXPECT_EQ(descriptor_count(), before);
  EXPECT_EQ(access((directory.path() + "/rasp_install_id").c_str(), F_OK), -1);
}

TEST(PrivateStorageFault, acquire_whenLockIsBusy_staysNonblockingAndDoesNotRetry) {
  const test_support::TemporaryDirectory directory;
  lock_calls() = 0;
  const auto result = acquire_fault(directory.path(), Fault::kBusy);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), StorageError::kBusy);
  EXPECT_EQ(lock_calls(), 1);
}

/// Verifies a nonbusy error cannot trigger retries or leak a descriptor in the legacy API.
void check_legacy_error(Fault fault) {
  const test_support::TemporaryDirectory directory;
  const auto before = descriptor_count();
  lock_calls() = 0;
  active_fault() = fault;
  const auto result = load_or_create_install_id(directory.path());
  active_fault() = Fault::kNone;
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(lock_calls(), 1);
  EXPECT_EQ(descriptor_count(), before);
}

TEST(PrivateStorageFault, legacy_whenLockIoReadOrRandomFails_doesNotRetryOtherErrors) {
  check_legacy_error(Fault::kLock);
  check_legacy_error(Fault::kRead);
  check_legacy_error(Fault::kRandom);
}

/// Validates one failing persistence boundary and its retry without nesting assertions inside a fault loop.
void check_publication_fault(Fault fault) {
  const test_support::TemporaryDirectory directory;
  const auto failed = acquire_fault(directory.path(), fault);
  ASSERT_FALSE(failed.has_value()) << static_cast<int>(fault);
  const auto existing = test_support::read_file(directory.path() + "/rasp_install_id");
  auto recovered = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(recovered.has_value()) << static_cast<int>(fault);
  EXPECT_TRUE(!existing.has_value() || recovered->install_id() == *existing);
  auto again = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(again.has_value());
  EXPECT_EQ(again->install_id(), recovered->install_id());
  EXPECT_EQ(access((directory.path() + "/rasp_install_id.private.tmp").c_str(), F_OK), -1);
}

TEST(PrivateStorageFault, acquire_whenPublicationBoundaryFails_returnsErrorAndSafeRetryKeepsOneIdentity) {
  for (const Fault fault : {
           Fault::kRandom,
           Fault::kShortWrite,
           Fault::kFileSync,
           Fault::kPublishSync,
           Fault::kPublish,
           Fault::kCloseFile,
           Fault::kCloseLock,
           Fault::kForeignDirectory,
           Fault::kForeignFile,
           Fault::kForeignGroup,
           Fault::kChangedInode,
           Fault::kReadOnly,
           Fault::kLock,
       }) {
    check_publication_fault(fault);
  }
}

TEST(PrivateStorageFault, acquire_whenExistingIdentityReadFails_preservesIdentityAndReportsError) {
  const test_support::TemporaryDirectory directory;
  auto first = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(first.has_value());
  auto failed = acquire_fault(directory.path(), Fault::kRead);
  ASSERT_FALSE(failed.has_value());
  EXPECT_EQ(failed.error(), StorageError::kIoError);
  auto retry = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(retry.has_value());
  EXPECT_EQ(retry->install_id(), first->install_id());
}

TEST(PrivateStorageFault, acquire_whenStaleTemporaryCannotBeRemoved_doesNotPublishOrDeleteIt) {
  const test_support::TemporaryDirectory directory;
  const std::string temporary = directory.path() + "/rasp_install_id.private.tmp";
  ASSERT_TRUE(test_support::write_file(temporary, "partial"));
  EXPECT_FALSE(acquire_fault(directory.path(), Fault::kUnlink).has_value());
  EXPECT_EQ(test_support::read_file(temporary), "partial");
  EXPECT_EQ(access((directory.path() + "/rasp_install_id").c_str(), F_OK), -1);
  EXPECT_TRUE(posix::acquire_private_storage_at(directory.path()).has_value());
}
}  // namespace
}  // namespace rasp

namespace rasp {
namespace {
TEST(PrivateStorageFault, acquire_whenCompetitorAppearsAtAtomicPublication_neverReplacesItsBytesOrInode) {
  const test_support::TemporaryDirectory directory;
  const auto result = acquire_fault(directory.path(), Fault::kCompetingIdentity);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), StorageError::kBusy);
  constexpr std::string_view kCompetitor = "00000000-1111-4222-8333-444444444444";
  const std::string path = directory.path() + "/rasp_install_id";
  EXPECT_EQ(test_support::read_file(path), kCompetitor);
  struct stat after{};
  ASSERT_EQ(lstat(path.c_str(), &after), 0);
  EXPECT_EQ(after.st_ino, competing_inode().st_ino);
  EXPECT_EQ(after.st_dev, competing_inode().st_dev);
  EXPECT_EQ(after.st_nlink, 1U);
  EXPECT_EQ(access((directory.path() + "/rasp_install_id.private.tmp").c_str(), F_OK), -1);
  const auto retry = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(retry.has_value());
  EXPECT_EQ(retry->install_id(), kCompetitor);
}

TEST(PrivateStorageFault, acquire_whenCrashLeavesPublishedTwoLinkIdentity_recoversOnlyTheOwnedTemporary) {
  const test_support::TemporaryDirectory directory;
  const auto interrupted = acquire_fault(directory.path(), Fault::kPublishedCleanup);
  ASSERT_FALSE(interrupted.has_value());
  const std::string path = directory.path() + "/rasp_install_id";
  const auto identity = test_support::read_file(path);
  ASSERT_TRUE(identity.has_value());
  struct stat before{};
  ASSERT_EQ(lstat(path.c_str(), &before), 0);
  ASSERT_EQ(before.st_nlink, 2U);
  const auto retry = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(retry.has_value());
  EXPECT_EQ(retry->install_id(), *identity);
  struct stat after{};
  ASSERT_EQ(lstat(path.c_str(), &after), 0);
  EXPECT_EQ(after.st_ino, before.st_ino);
  EXPECT_EQ(after.st_nlink, 1U);
  EXPECT_EQ(access((directory.path() + "/rasp_install_id.private.tmp").c_str(), F_OK), -1);
}
}  // namespace
}  // namespace rasp

namespace rasp {
namespace {
TEST(PrivateStorageFault, close_whenKernelReportsFailure_returnsErrorWithoutRetryingOrRetainingBorrowedDescriptor) {
  const test_support::TemporaryDirectory directory;
  auto storage = posix::acquire_private_storage_at(directory.path());
  ASSERT_TRUE(storage.has_value());
  active_fault() = Fault::kCloseDirectory;
  const auto result = storage->close();
  active_fault() = Fault::kNone;
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), StorageError::kIoError);
  EXPECT_EQ(storage->native_handle(), -1);
  EXPECT_TRUE(storage->close().has_value());
}
}  // namespace
}  // namespace rasp
