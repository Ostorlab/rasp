/// load_or_create_install_id: the id of this install of the app, which the runtime creates on the first launch and
/// keeps in the app's own storage.

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace rasp {

/// The name of the file that keeps the install id, in the folder each platform gives.
inline constexpr std::string_view kInstallIdFileName = "rasp_install_id";

/// Reads the install id kept in `directory`, or creates one and keeps it there.
///
/// The id is a random UUID (version 4) from the OS secure entropy API, written as 36 lowercase characters such as
/// `0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b`. It says nothing about the device or the user, so it changes when the app is
/// installed again. A corrupt, noncanonical or zero kept identity returns unavailable without rotation.
///
/// The processes of an app share the folder, and several may start at once. A process that finds no id takes the
/// nonblocking exclusive lock of `rasp_install_id.lock`, next to the id's file. Only busy contention is retried:
/// at most 11 attempts with ten 5 ms sleeps (at most 50 ms of requested retry delay). Scheduler and filesystem I/O
/// can take longer; persistent contention still returns unavailable. Other errors fail without retry. It reads under
/// lock and creates only when absent, so processes share the same id. The new id is fsynced in an exclusive temporary
/// file and atomically linked without replacing any competing identity. Only the owned temporary is removed; file
/// metadata and parent directory are synced before success.
///
/// Valid same-parent, same-UID, single-link regular legacy 0644 identities are hardened in place to 0600 only after
/// validating their contents and inode stability, with metadata fsync before success. No guessed path is migrated.
///
/// It reads and writes files, so it runs on the runtime's own thread, never at load time.
///
/// @param directory The folder of the app's own storage that keeps the id. It must exist.
/// @return The id, or nothing when the kept id can't be read and a new one can't be kept.
[[nodiscard]] std::optional<std::string> load_or_create_install_id(std::string_view directory);

}  // namespace rasp
