/// load_install_id: the random id of this installation of the app, kept in a file from one launch to the next.

#pragma once

#include <string>
#include <string_view>

#include "rasp/util/uuid.h"

namespace rasp::ios {

/// The name of the file that holds the install id, inside the directory given to load_install_id.
inline constexpr std::string_view kInstallIdFileName = "co.ostorlab.rasp.install";

/// Gives the install id of this installation of the app, kept in a file in `directory`.
///
/// On the first launch there's no stored id: it makes a random one and stores it, creating `directory` when it
/// doesn't exist yet (its parent must exist). Later launches read the same id back. A file that isn't exactly 16
/// bytes long is replaced with a new id. When the file exists but can't be read, for example while the phone is
/// locked and the file is protected, it gives a new random id for this launch only and leaves the file untouched, so
/// the stored id is never lost. Storing goes through a temporary file renamed over the real one, so a crash never
/// leaves half an id. When storing fails, the new id still serves this launch.
///
/// @param directory The directory that holds the file, such as the app's Library/Application Support.
/// @return The stored install id, or a new random one.
[[nodiscard]] Uuid load_install_id(const std::string& directory) noexcept;

}  // namespace rasp::ios
