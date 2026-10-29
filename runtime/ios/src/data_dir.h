/// The app's data directory on iOS, for persisting the installation id.

#pragma once

#include <optional>
#include <string>

namespace rasp::ios {

/// The app's Library directory, such as `/var/mobile/Containers/Data/Application/<uuid>/Library`.
///
/// The Library directory is private to the app, survives app updates but is removed on uninstall, and is not backed up
/// to iCloud by default. It is the right place for an install-scoped id: it lives as long as the install.
///
/// @return The directory path, or nothing when it cannot be determined.
[[nodiscard]] std::optional<std::string> data_dir();

}  // namespace rasp::ios
