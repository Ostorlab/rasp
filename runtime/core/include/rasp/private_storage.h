/// Additive worker-thread capability for a private durable queue and its local install identity.
#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace rasp {
namespace posix {
struct StorageAccess;
}

/// Capability failures, never malware observations or a fabricated identity.
enum class StorageError : std::uint8_t {
  kUnavailable,
  kBusy,
  kInvalidDirectory,
  kUnsafeFile,
  kInvalidIdentity,
  kIoError,
  kRandomUnavailable,
  kBackupExclusionFailed,
};

/// Owns a verified private queue directory and the identity to use with its payloads.
class PrivateStorage {
 public:
  /// Releases the descriptor; use close() when the caller must observe a close failure.
  ~PrivateStorage();
  PrivateStorage(const PrivateStorage&) = delete;
  PrivateStorage& operator=(const PrivateStorage&) = delete;
  /// Transfers descriptor ownership without filesystem operations.
  /// @param other The capability to consume.
  PrivateStorage(PrivateStorage&& other) noexcept;
  PrivateStorage& operator=(PrivateStorage&&) = delete;
  /// Borrows the directory descriptor for bounded descriptor-relative operations; never close this borrowed value.
  /// @return A directory descriptor, or -1 after close/move.
  [[nodiscard]] int native_handle() const;
  /// Borrows canonical nonzero UUID text; future transport must use it with this queue instead of startup Config.
  /// @return Text valid for this object's lifetime, including after close; moved-from text is unspecified.
  [[nodiscard]] std::string_view install_id() const;
  /// Releases the descriptor once; close is never retried because a descriptor may already have been reused.
  /// @return Success (also if already closed), or kIoError. This does not flush consumer writes.
  [[nodiscard]] std::expected<void, StorageError> close();

 private:
  friend struct posix::StorageAccess;
  /// Takes ownership of a verified descriptor and identity from the platform provider.
  PrivateStorage(int descriptor, std::string install_id);
  int descriptor_;
  std::string install_id_;
};

/// Queries the platform afresh, enabling late supported Application attachment without reinitializing plugins.
/// Call from a worker only; filesystem I/O has no hard deadline, but lock acquisition never waits.
/// @return An owned queue capability, or explicit unavailable/error; no fallback directory or zero identity.
[[nodiscard]] std::expected<PrivateStorage, StorageError> acquire_private_storage();
}  // namespace rasp
