/// Internal POSIX implementation shared by actual Android/iOS providers and native filesystem fixtures.
#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <sys/types.h>

#include "rasp/private_storage.h"

namespace rasp::posix {
/// Selects platform search descriptors for ancestors; final owned directories always use readable descriptors.
/// @return O_PATH on Android/Linux; O_SEARCH on iOS18+/macOS15+, otherwise readable O_RDONLY ancestors.
[[nodiscard]] int directory_search_flags();

/// Recognizes only operating-system owners allowed to provide immutable ancestor aliases.
/// @param owner Alias or parent effective Unix owner.
/// @return Root/system on Android, root on iOS/macOS; application-owned aliases remain forbidden.
[[nodiscard]] bool platform_alias_owner(uid_t owner);

/// Optional platform hook, called on the private child before identity creation or exposure to consumers.
using PreparePrivateDirectory = bool (*)(std::string_view child_path);

/// Opens bounded components with no-follow handles, permitting only verified privileged non-app-writable ancestor
/// aliases. Final directories and app-controlled intermediate symlinks are never followed; the final directory must be
/// private.
/// @param path Platform-selected directory, never inferred from process name by the new provider.
/// @return Owned descriptor on success; caller must close it.
[[nodiscard]] std::expected<int, StorageError> open_private_directory(std::string_view path);

/// Names both public platform path forms explicitly to prevent accidental argument reversal.
struct PlatformDirectoryPaths {
  /// Absolute path returned by the platform API.
  std::string_view absolute;
  /// Canonical form returned by the platform API.
  std::string_view canonical;
};

/// Pins a public platform path, allowing only privileged non-app-writable ancestor symlinks and matching canonical
/// inode.
/// @param paths The absolute and canonical forms of the same public platform directory.
/// @return Owned validated parent descriptor, or explicit failure.
[[nodiscard]] std::expected<int, StorageError> open_platform_directory(PlatformDirectoryPaths paths);

/// Creates the capability from an already pinned platform parent; always consumes the descriptor, including on failure.
/// @param owned_parent Owned parent descriptor from open_platform_directory/open_private_directory.
/// @param root Canonical platform path used only for platform backup/protection policy.
/// @param prepare Optional policy applied before identity creation and queue exposure.
/// @return Owned child and matching identity, or explicit failure.
[[nodiscard]] std::expected<PrivateStorage, StorageError> acquire_private_storage_in(
    int owned_parent, std::string_view root, PreparePrivateDirectory prepare = nullptr);

/// Reads/creates a canonical identity under a nonblocking validated private lock; never rotates corrupt identities.
/// @param directory Borrowed verified private parent descriptor.
/// @return Durable identity, or an explicit failure.
[[nodiscard]] std::expected<std::string, StorageError> load_private_install_id(int directory);

/// Creates/validates the fixed private child and pairs it with the verified parent's identity.
/// @param root The platform directory; host tests supply a fixture explicitly.
/// @param prepare Optional backup/protection setup before the capability may be used.
/// @return Owned descriptor and identity, or explicit failure with no queue capability.
[[nodiscard]] std::expected<PrivateStorage, StorageError> acquire_private_storage_at(
    std::string_view root, PreparePrivateDirectory prepare = nullptr);
}  // namespace rasp::posix
