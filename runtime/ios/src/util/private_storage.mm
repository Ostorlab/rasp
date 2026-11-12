/// Supported iOS sandbox storage; protection and verified backup exclusion precede queue capability exposure.
#include "rasp/private_storage.h"

#import <Foundation/Foundation.h>
#include <array>
#include <cstddef>
#include <expected>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "rasp/posix/private_storage.h"

namespace rasp {
namespace {
constexpr std::size_t kMaxPathBytes = 4096;

/// Converts bounded native filesystem bytes to an NSURL without changing process environment or global state.
[[nodiscard]] NSURL* storage_url(std::string_view path) {
  const std::string terminated(path);
  return [NSURL fileURLWithFileSystemRepresentation:terminated.c_str() isDirectory:NO relativeToURL:nil];
}

/// Copies a platform filesystem representation into bounded owned memory using the public NSURL API.
[[nodiscard]] std::expected<std::string, StorageError> filesystem_path(NSURL* url) {
  std::string path(kMaxPathBytes, '\0');
  if (url == nil || [url getFileSystemRepresentation:path.data() maxLength:path.size()] == NO) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  const std::size_t terminator = path.find('\0');
  if (terminator == std::string::npos || terminator == 0) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  path.resize(terminator);
  return path;
}

/// Sets and reads back backup exclusion and iOS data protection; any unsupported/failing policy is unavailable.
[[nodiscard]] bool protect_and_exclude(NSURL* url) {
  if (url == nil) {
    return false;
  }
  NSString* const path = [url path];
  if (path == nil) {
    return false;
  }
  NSFileManager* const manager = [NSFileManager defaultManager];
  if ([manager setAttributes:@{NSFileProtectionKey : NSFileProtectionCompleteUntilFirstUserAuthentication}
                ofItemAtPath:path
                       error:nullptr] == NO) {
    return false;
  }
  NSDictionary* const attributes = [manager attributesOfItemAtPath:path error:nullptr];
  if (attributes == nil ||
      [attributes[NSFileProtectionKey] isEqual:NSFileProtectionCompleteUntilFirstUserAuthentication] == NO) {
    return false;
  }
  if ([url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nullptr] == NO) {
    return false;
  }
  NSNumber* excluded = nil;
  return [url getResourceValue:&excluded forKey:NSURLIsExcludedFromBackupKey error:nullptr] != NO &&
         [excluded isKindOfClass:[NSNumber class]] != NO && [excluded boolValue] != NO;
}

/// Runs before any identity creation and before the caller can write sensitive queue payloads.
[[nodiscard]] bool prepare_directory(std::string_view path) { return protect_and_exclude(storage_url(path)); }

/// Pins the validated identity while applying URL policies, verifies inode/content stability and fsyncs policy
/// metadata.
[[nodiscard]] bool exclude_owned_identity(const PrivateStorage& storage, NSURL* root) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): openat is the required no-follow descriptor-relative API.
  const int parent = openat(storage.native_handle(), "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (parent < 0) {
    return false;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): openat is the required no-follow descriptor-relative API.
  const int file = openat(parent, "rasp_install_id", O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  struct stat before{};
  struct stat entry{};
  std::array<char, 37> bytes{};
  const bool valid = file >= 0 && fstat(file, &before) == 0 && S_ISREG(before.st_mode) && before.st_uid == geteuid() &&
                     before.st_nlink == 1 && (before.st_mode & 07777U) == 0600 &&
                     fstatat(parent, "rasp_install_id", &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
                     entry.st_dev == before.st_dev && entry.st_ino == before.st_ino && S_ISREG(entry.st_mode) &&
                     pread(file, bytes.data(), bytes.size(), 0) == 36 &&
                     std::string_view(bytes.data(), 36) == storage.install_id();
  NSURL* const identity_url = [root URLByAppendingPathComponent:@"rasp_install_id" isDirectory:NO];
  struct stat named{};
  const char* path = [identity_url fileSystemRepresentation];
  const bool same_path = valid && path != nullptr && lstat(path, &named) == 0 && S_ISREG(named.st_mode) &&
                         named.st_dev == before.st_dev && named.st_ino == before.st_ino;
  const bool excluded = same_path && protect_and_exclude(identity_url);
  struct stat after{};
  const bool stable = excluded && fstat(file, &after) == 0 && after.st_dev == before.st_dev &&
                      after.st_ino == before.st_ino && after.st_nlink == 1 && after.st_size == before.st_size &&
                      fstatat(parent, "rasp_install_id", &entry, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(entry.st_mode) &&
                      entry.st_dev == before.st_dev && entry.st_ino == before.st_ino && lstat(path, &named) == 0 &&
                      S_ISREG(named.st_mode) && named.st_dev == before.st_dev && named.st_ino == before.st_ino;
  const bool synced = stable && fsync(file) == 0 && fsync(parent) == 0;
  const bool file_closed = file < 0 || close(file) == 0;
  const bool parent_closed = close(parent) == 0;
  return synced && file_closed && parent_closed;
}

/// Resolves platform-owned ancestor aliases, validates the final directory, then verifies the returned queue owner.
[[nodiscard]] std::expected<PrivateStorage, StorageError> acquire_in_pool() {
  NSURL* const root = [[NSFileManager defaultManager] URLForDirectory:NSApplicationSupportDirectory
                                                             inDomain:NSUserDomainMask
                                                    appropriateForURL:nil
                                                               create:YES
                                                                error:nullptr];
  if (root == nil || [root isFileURL] == NO) {
    return std::unexpected(StorageError::kUnavailable);
  }
  const auto original_path = filesystem_path(root);
  if (!original_path.has_value()) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  struct stat original{};
  if (lstat(original_path->c_str(), &original) != 0 || !S_ISDIR(original.st_mode)) {
    return std::unexpected(StorageError::kUnavailable);
  }
  NSURL* const canonical = [root URLByResolvingSymlinksInPath];
  const auto path = filesystem_path(canonical);
  if (!path.has_value()) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  const auto parent_directory = posix::open_platform_directory({.absolute = *original_path, .canonical = *path});
  if (!parent_directory.has_value()) {
    return std::unexpected(parent_directory.error());
  }
  auto storage = posix::acquire_private_storage_in(*parent_directory, *path, prepare_directory);
  if (!storage.has_value()) {
    return storage;
  }
  struct stat parent{};
  struct stat after{};
  if (fstatat(storage->native_handle(), "..", &parent, AT_SYMLINK_NOFOLLOW) != 0 ||
      lstat(original_path->c_str(), &after) != 0 || !S_ISDIR(after.st_mode) || original.st_dev != parent.st_dev ||
      original.st_ino != parent.st_ino || after.st_dev != parent.st_dev || after.st_ino != parent.st_ino) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  if (!exclude_owned_identity(*storage, canonical)) {
    return std::unexpected(StorageError::kBackupExclusionFailed);
  }
  return storage;
}
}  // namespace

std::expected<PrivateStorage, StorageError> acquire_private_storage() {
  @autoreleasepool {
    return acquire_in_pool();
  }
}
}  // namespace rasp
