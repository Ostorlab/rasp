/// Descriptor-relative private-directory ownership and durable, nonblocking install identity creation.
#include "rasp/posix/private_storage.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "rasp/private_storage.h"
#include "util/posix_file.h"

namespace rasp {
PrivateStorage::PrivateStorage(int descriptor, std::string install_id)
    : descriptor_(descriptor), install_id_(std::move(install_id)) {}
PrivateStorage::~PrivateStorage() { static_cast<void>(close()); }
PrivateStorage::PrivateStorage(PrivateStorage&& other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)), install_id_(std::move(other.install_id_)) {}
int PrivateStorage::native_handle() const { return descriptor_; }
std::string_view PrivateStorage::install_id() const { return install_id_; }
std::expected<void, StorageError> PrivateStorage::close() {
  const int descriptor = std::exchange(descriptor_, -1);
  if (descriptor >= 0 && ::close(descriptor) != 0) {
    return std::unexpected(StorageError::kIoError);
  }
  return {};
}

namespace posix {
/// Constructs only after the platform and common validators have succeeded.
struct StorageAccess {
  /// Takes ownership of a validated directory and paired identity.
  [[nodiscard]] static PrivateStorage make(int descriptor, std::string install_id) {
    return {descriptor, std::move(install_id)};
  }
};
namespace {
constexpr const char* kChild = "rasp_private";
constexpr const char* kIdentity = "rasp_install_id";
constexpr const char* kLock = "rasp_install_id.lock";
constexpr const char* kTemporary = "rasp_install_id.private.tmp";
constexpr std::size_t kUuidLength = 36;
constexpr std::size_t kMaxPath = 4096;
constexpr int kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
constexpr int kReadFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
constexpr std::string_view kHex = "0123456789abcdef";

/// Owns intermediate descriptors without mistaking destructor cleanup for checked successful publication.
class Descriptor {
 public:
  explicit Descriptor(int value) : value_(value) {}
  ~Descriptor() { static_cast<void>(close()); }
  Descriptor(const Descriptor&) = delete;
  Descriptor& operator=(const Descriptor&) = delete;
  Descriptor(Descriptor&&) = delete;
  Descriptor& operator=(Descriptor&&) = delete;
  [[nodiscard]] int get() const { return value_; }
  [[nodiscard]] int release() { return std::exchange(value_, -1); }
  /// Adopts a descriptor only after the previous one has been closed.
  void adopt(int value) { value_ = value; }
  [[nodiscard]] bool close() {
    const int value = release();
    return value < 0 || ::close(value) == 0;
  }

 private:
  int value_;
};

/// Validates directory ownership and permissions without requiring Android parents to forbid group traversal.
[[nodiscard]] bool private_directory(int descriptor) {
  struct stat info{};
  return fstat(descriptor, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == geteuid() &&
         (info.st_mode & 0002U) == 0 &&
         ((info.st_mode & 0020U) == 0 || (info.st_gid == getegid() && info.st_gid == geteuid())) &&
         (info.st_mode & 0700U) == 0700;
}

/// Matches descriptor metadata with its no-follow directory entry and refuses links, devices, FIFOs and weak modes.
[[nodiscard]] bool private_file(int directory, const char* name, int descriptor, struct stat& info,
                                bool legacy_identity = false, unsigned int link_count = 1) {
  struct stat entry{};
  return fstat(descriptor, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
         ((info.st_mode & 07777U) == 0600 || (legacy_identity && (info.st_mode & 07777U) == 0644)) &&
         std::cmp_equal(info.st_nlink, link_count) && fstatat(directory, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
         entry.st_dev == info.st_dev && entry.st_ino == info.st_ino && S_ISREG(entry.st_mode);
}

/// Accepts canonical lowercase, nonzero UUIDs only, including valid legacy identifiers kept in place.
[[nodiscard]] bool canonical_uuid(std::string_view text) {
  if (text.size() != kUuidLength) {
    return false;
  }
  bool nonzero = false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (text[index] != '-') {
        return false;
      }
    } else {
      if (!kHex.contains(text[index])) {
        return false;
      }
      nonzero = nonzero || text[index] != '0';
    }
  }
  return nonzero;
}

/// Reads at most 37 bytes and checks metadata again, distinguishing absent identity from corruption and I/O errors.
[[nodiscard]] std::expected<std::optional<std::string>, StorageError> read_identity(int directory) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open/openat are required libc APIs; all flags/modes are explicit.
  Descriptor file(openat(directory, kIdentity, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (file.get() < 0) {
    if (errno == ENOENT) {
      return std::nullopt;
    }
    return std::unexpected(errno == ELOOP ? StorageError::kUnsafeFile : StorageError::kIoError);
  }
  struct stat before{};
  if (!private_file(directory, kIdentity, file.get(), before, true)) {
    return std::unexpected(StorageError::kUnsafeFile);
  }
  if (std::cmp_not_equal(before.st_size, kUuidLength)) {
    return std::unexpected(StorageError::kInvalidIdentity);
  }
  std::array<char, kUuidLength + 1> bytes{};
  const ssize_t count = read(file.get(), bytes.data(), bytes.size());
  struct stat after{};
  if (count < 0) {
    return std::unexpected(StorageError::kIoError);
  }
  if (!private_file(directory, kIdentity, file.get(), after, true) || before.st_size != after.st_size ||
      before.st_mtime != after.st_mtime || before.st_ctime != after.st_ctime) {
    return std::unexpected(StorageError::kUnsafeFile);
  }
  if (std::cmp_not_equal(count, kUuidLength) || !canonical_uuid(std::string_view(bytes.data(), kUuidLength))) {
    return std::unexpected(StorageError::kInvalidIdentity);
  }
  if (((after.st_mode & 07777U) != 0600 && fchmod(file.get(), static_cast<mode_t>(0600)) != 0) ||
      fsync(file.get()) != 0 || !private_file(directory, kIdentity, file.get(), after) || !file.close() ||
      fsync(directory) != 0) {
    return std::unexpected(StorageError::kIoError);
  }
  return std::string(bytes.data(), kUuidLength);
}

/// Gets secure bytes through the supported OS API; entropy failures never fall back to predictable identifiers.
[[nodiscard]] std::expected<std::string, StorageError> random_identity() {
  std::array<std::uint8_t, 16> bytes{};
  if (getentropy(bytes.data(), bytes.size()) != 0) {
    return std::unexpected(StorageError::kRandomUnavailable);
  }
  bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0fU) | 0x40U);
  bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3fU) | 0x80U);
  std::string text;
  text.reserve(kUuidLength);
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    if (index == 4 || index == 6 || index == 8 || index == 10) {
      text.push_back('-');
    }
    text.push_back(kHex[std::span(bytes)[index] >> 4U]);
    text.push_back(kHex[std::span(bytes)[index] & 0x0fU]);
  }
  return text;
}

/// Removes only a previously validated single-link stale temporary regular file while holding the identity lock.
[[nodiscard]] bool remove_stale_temporary(int directory) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open/openat are required libc APIs; all flags/modes are explicit.
  Descriptor stale(openat(directory, kTemporary, kReadFlags));
  if (stale.get() < 0) {
    return errno == ENOENT;
  }
  struct stat info{};
  if (!private_file(directory, kTemporary, stale.get(), info) || !stale.close()) {
    return false;
  }
  return unlinkat(directory, kTemporary, 0) == 0;
}

/// Removes only this creation's temporary inode; a replaced directory entry is never deleted as cleanup.
[[nodiscard]] bool unlink_owned_temporary(int directory, const struct stat& owned) {
  struct stat entry{};
  return fstatat(directory, kTemporary, &entry, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(entry.st_mode) &&
         entry.st_uid == geteuid() && entry.st_dev == owned.st_dev && entry.st_ino == owned.st_ino &&
         unlinkat(directory, kTemporary, 0) == 0;
}

/// Recovers a crash after atomic linking only when both names prove the exact two-link owned canonical identity.
[[nodiscard]] bool recover_linked_temporary(int directory) {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required bounded POSIX no-follow API.
  Descriptor temporary(openat(directory, kTemporary, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (temporary.get() < 0) {
    return errno == ENOENT;
  }
  struct stat info{};
  if (private_file(directory, kTemporary, temporary.get(), info)) {
    return temporary.close();
  }
  if (!private_file(directory, kTemporary, temporary.get(), info, false, 2) ||
      !private_file(directory, kIdentity, temporary.get(), info, false, 2)) {
    return false;
  }
  std::array<char, kUuidLength + 1> bytes{};
  if (pread(temporary.get(), bytes.data(), bytes.size(), 0) != static_cast<ssize_t>(kUuidLength) ||
      !canonical_uuid(std::string_view(bytes.data(), kUuidLength)) || fsync(temporary.get()) != 0 ||
      !private_file(directory, kIdentity, temporary.get(), info, false, 2) ||
      !unlink_owned_temporary(directory, info)) {
    return false;
  }
  const bool synced = fsync(temporary.get()) == 0 && fsync(directory) == 0;
  const bool closed = temporary.close();
  return synced && closed;
}

/// Atomically links without replacing any competing identity, preserving that identity on EEXIST or later failure.
[[nodiscard]] std::expected<void, StorageError> publish_temporary(int directory, int descriptor,
                                                                  const struct stat& owned) {
  if (linkat(directory, kTemporary, directory, kIdentity, 0) != 0) {
    const int publish_error = errno;
    const bool cleaned = unlink_owned_temporary(directory, owned);
    const bool synced = fsync(directory) == 0;
    if (!cleaned || !synced) {
      return std::unexpected(StorageError::kIoError);
    }
    return std::unexpected(publish_error == EEXIST ? StorageError::kBusy : StorageError::kIoError);
  }
  struct stat linked{};
  if (!private_file(directory, kTemporary, descriptor, linked, false, 2) ||
      !private_file(directory, kIdentity, descriptor, linked, false, 2) || !unlink_owned_temporary(directory, owned) ||
      fsync(descriptor) != 0) {
    return std::unexpected(StorageError::kIoError);
  }
  return {};
}

/// Publishes a whole fsynced identity using portable atomic no-replace linkat, then syncs and verifies it.
[[nodiscard]] std::expected<std::string, StorageError> create_identity(int directory) {
  auto identity = random_identity();
  if (!identity.has_value()) {
    return std::unexpected(identity.error());
  }
  if (!remove_stale_temporary(directory)) {
    return std::unexpected(StorageError::kUnsafeFile);
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX exclusive private file creation.
  Descriptor file(openat(directory, kTemporary, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                         static_cast<mode_t>(0600)));
  if (file.get() < 0) {
    return std::unexpected(StorageError::kIoError);
  }
  struct stat owned{};
  const bool written = private_file(directory, kTemporary, file.get(), owned) &&
                       write(file.get(), identity->data(), identity->size()) == static_cast<ssize_t>(identity->size());
  if (!written || fsync(file.get()) != 0 || !private_file(directory, kTemporary, file.get(), owned)) {
    static_cast<void>(unlink_owned_temporary(directory, owned));
    return std::unexpected(StorageError::kIoError);
  }
  const auto published = publish_temporary(directory, file.get(), owned);
  const bool closed = file.close();
  const bool synced = fsync(directory) == 0;
  if (!closed || !synced) {
    return std::unexpected(StorageError::kIoError);
  }
  if (!published.has_value()) {
    return std::unexpected(published.error());
  }
  const auto kept = read_identity(directory);
  if (!kept.has_value() || !kept->has_value() || **kept != *identity) {
    return std::unexpected(StorageError::kUnsafeFile);
  }
  return identity;
}
}  // namespace

namespace {
/// Permits only an alias whose privileged parent cannot be modified by this app or its effective group.
[[nodiscard]] bool privileged_alias(int parent, const char* component, struct stat& link_info) {
  struct stat parent_info{};
  return fstatat(parent, component, &link_info, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(link_info.st_mode) &&
         fstat(parent, &parent_info) == 0 && link_info.st_uid != geteuid() && parent_info.st_uid != geteuid() &&
         platform_alias_owner(link_info.st_uid) && platform_alias_owner(parent_info.st_uid) &&
         (link_info.st_uid == 0 || link_info.st_uid == parent_info.st_uid) && (parent_info.st_mode & 0022U) == 0;
}

/// Follows one proven OS alias and checks that the privileged symlink inode stayed unchanged.
[[nodiscard]] int open_alias(int parent, const std::string& component, int flags) {
  struct stat link_info{};
  if (!privileged_alias(parent, component.c_str(), link_info)) {
    return -1;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): required POSIX API with explicit typed flags.
  Descriptor next(openat(parent, component.c_str(),
                         static_cast<int>(static_cast<unsigned int>(flags) & ~static_cast<unsigned int>(O_NOFOLLOW))));
  struct stat after{};
  if (fstatat(parent, component.c_str(), &after, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISLNK(after.st_mode) ||
      after.st_dev != link_info.st_dev || after.st_ino != link_info.st_ino) {
    return -1;
  }
  return next.release();
}

/// Traverses bounded directory components, permitting only privileged immutable ancestor aliases for platform paths.
std::expected<int, StorageError> open_directory(std::string_view path, bool platform_aliases) {
  if (path.empty() || path.size() >= kMaxPath || path.front() != '/' || path.back() == '/' || path.contains('\0')) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  const int search_flags = static_cast<int>(static_cast<unsigned int>(directory_search_flags()) | O_DIRECTORY |
                                            O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open/openat are required libc APIs; all flags/modes are explicit.
  Descriptor cursor(open("/", search_flags));
  if (cursor.get() < 0) {
    return std::unexpected(StorageError::kIoError);
  }
  std::size_t offset = 1;
  for (std::size_t components = 0; offset < path.size() && components < 128; ++components) {
    const std::size_t separator = path.find('/', offset);
    const std::string component(
        path.substr(offset, separator == std::string_view::npos ? path.size() - offset : separator - offset));
    if (component.empty() || component == "." || component == ".." || component.size() > 255) {
      return std::unexpected(StorageError::kInvalidDirectory);
    }
    const int flags = separator == std::string_view::npos ? kDirectoryFlags : search_flags;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open/openat are required libc APIs; all flags/modes are explicit.
    Descriptor next(openat(cursor.get(), component.c_str(), flags));
    if (next.get() < 0 && platform_aliases && separator != std::string_view::npos) {
      next.adopt(open_alias(cursor.get(), component, flags));
    }
    if (next.get() < 0 || !cursor.close()) {
      return std::unexpected(StorageError::kInvalidDirectory);
    }
    if (separator == std::string_view::npos) {
      Descriptor final_directory(next.release());
      if (!private_directory(final_directory.get())) {
        return std::unexpected(StorageError::kInvalidDirectory);
      }
      return final_directory.release();
    }
    cursor.adopt(next.release());
    offset = separator + 1;
  }
  return std::unexpected(StorageError::kInvalidDirectory);
}

}  // namespace

std::expected<int, StorageError> open_private_directory(std::string_view path) { return open_directory(path, true); }

std::expected<int, StorageError> open_platform_directory(PlatformDirectoryPaths paths) {
  const auto original = open_directory(paths.absolute, true);
  if (!original.has_value()) {
    return std::unexpected(original.error());
  }
  Descriptor parent(*original);
  const auto resolved = open_private_directory(paths.canonical);
  if (!resolved.has_value()) {
    return std::unexpected(resolved.error());
  }
  Descriptor resolved_parent(*resolved);
  struct stat before{};
  struct stat after{};
  if (fstat(parent.get(), &before) != 0 || fstat(resolved_parent.get(), &after) != 0 || before.st_dev != after.st_dev ||
      before.st_ino != after.st_ino || !resolved_parent.close()) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  return parent.release();
}

std::expected<std::string, StorageError> load_private_install_id(int directory) {
  if (!private_directory(directory)) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  Descriptor lock(
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open/openat are required libc APIs; all flags/modes are explicit.
      openat(directory, kLock, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, static_cast<mode_t>(0600)));
  struct stat info{};
  if (lock.get() < 0 || !private_file(directory, kLock, lock.get(), info)) {
    return std::unexpected(StorageError::kUnsafeFile);
  }
  if (flock(lock.get(), LOCK_EX | LOCK_NB) != 0) {
    return std::unexpected(errno == EWOULDBLOCK || errno == EAGAIN ? StorageError::kBusy : StorageError::kIoError);
  }
  if (!private_file(directory, kLock, lock.get(), info) || !recover_linked_temporary(directory)) {
    return std::unexpected(StorageError::kUnsafeFile);
  }
  auto kept = read_identity(directory);
  if (!kept.has_value()) {
    return std::unexpected(kept.error());
  }
  auto identity =
      kept->has_value() ? std::expected<std::string, StorageError>(std::move(**kept)) : create_identity(directory);
  if (!private_file(directory, kLock, lock.get(), info) || !lock.close()) {
    return std::unexpected(StorageError::kIoError);
  }
  return identity;
}

std::expected<PrivateStorage, StorageError> acquire_private_storage_in(int owned_parent, std::string_view root,
                                                                       PreparePrivateDirectory prepare) {
  Descriptor parent(owned_parent);
  if (!private_directory(parent.get())) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  if (mkdirat(parent.get(), kChild, static_cast<mode_t>(0700)) != 0 && errno != EEXIST) {
    return std::unexpected(StorageError::kIoError);
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open/openat are required libc APIs; all flags/modes are explicit.
  Descriptor child(openat(parent.get(), kChild, kDirectoryFlags));
  struct stat child_info{};
  struct stat child_entry{};
  if (child.get() < 0 || !private_directory(child.get()) || fstat(child.get(), &child_info) != 0 ||
      (child_info.st_mode & 07777U) != 0700 || fstatat(parent.get(), kChild, &child_entry, AT_SYMLINK_NOFOLLOW) != 0 ||
      child_info.st_dev != child_entry.st_dev || child_info.st_ino != child_entry.st_ino) {
    return std::unexpected(StorageError::kInvalidDirectory);
  }
  if (prepare != nullptr && !prepare(std::string(root) + "/" + std::string(kChild))) {
    return std::unexpected(StorageError::kBackupExclusionFailed);
  }
  if (fstatat(parent.get(), kChild, &child_entry, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(child_entry.st_mode) ||
      child_info.st_dev != child_entry.st_dev || child_info.st_ino != child_entry.st_ino ||
      !private_directory(child.get()) || fstat(child.get(), &child_info) != 0 ||
      (child_info.st_mode & 07777U) != 0700 || fsync(child.get()) != 0 || fsync(parent.get()) != 0) {
    return std::unexpected(StorageError::kIoError);
  }
  auto identity = load_private_install_id(parent.get());
  if (!identity.has_value()) {
    return std::unexpected(identity.error());
  }
  if (!parent.close()) {
    return std::unexpected(StorageError::kIoError);
  }
  return StorageAccess::make(child.release(), std::move(*identity));
}
std::expected<PrivateStorage, StorageError> acquire_private_storage_at(std::string_view root,
                                                                       PreparePrivateDirectory prepare) {
  const auto parent = open_private_directory(root);
  if (!parent.has_value()) {
    return std::unexpected(parent.error());
  }
  return acquire_private_storage_in(*parent, root, prepare);
}
}  // namespace posix
}  // namespace rasp
