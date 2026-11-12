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
/// The id is a random UUID (version 4) from `arc4random_buf`, written as 36 lowercase characters such as
/// `0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b`. It says nothing about the device or the user, so it changes when the app is
/// installed again. A kept file that doesn't hold such a UUID is replaced with a new one.
///
/// The processes of an app share the folder, and several may start at once. A process that finds no id takes the
/// exclusive lock of `rasp_install_id.lock`, next to the id's file, reads the id again, and creates one only when there
/// still is none, so every process of the app gets the same id. The new id is written whole to a temporary file that
/// is then renamed, so a process never reads half an id.
///
/// It reads and writes files, so it runs on the runtime's own thread, never at load time.
///
/// @param directory The folder of the app's own storage that keeps the id. It must exist.
/// @return The id, or nothing when the kept id can't be read and a new one can't be kept.
[[nodiscard]] std::optional<std::string> load_or_create_install_id(std::string_view directory);

}  // namespace rasp
