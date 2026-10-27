/// The iOS virtualizer check: whether the app runs as a guest inside another app (an app virtualizer or container)
/// rather than installed on its own. It reports the surrounding context it can read, so the server can weigh it.

#pragma once

#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the virtualizer check and returns what it observed.
///
/// On a physical iOS device it reads the main executable's path and the loaded images. Anywhere else, on a simulator, a
/// Mac or a Linux host, there is no app container to reason about, so every observation is unsupported instead, so the
/// server still sees that the check ran.
///
/// @return One observation per source, in this order: virt.exec_path read through dyld, then virt.foreign_images read
/// through dyld.
[[nodiscard]] std::vector<Observation> virtualizer();

/// Reports whether the main executable's path `exec_path` lies outside the system's app-container layout.
///
/// A genuine install keeps the app under `/private/var/containers/Bundle/Application/<UUID>/<App>.app/`. An app
/// virtualizer loads the guest from its own container or data directory instead, so the executable's path is not inside
/// the system layout. This decides from the string alone, so the real path read can be tested through it.
///
/// @param exec_path The main executable's path, as dyld reports it.
/// @return One virt.exec_path observation read through dyld: true when the path is outside the expected container
/// layout, false when it is inside it.
[[nodiscard]] Observation observe_container_path(std::string_view exec_path);

/// Reports the loaded images whose path lies outside the legitimate roots, read from `image_paths`.
///
/// A genuine process loads only its own bundle's code, the system libraries under `/usr/lib` and `/System`, and the
/// shared cache. An app virtualizer maps its own runtime into the guest, from its container or data directory, so that
/// image's path is outside those roots. The probe reports each such path, up to a fixed limit, as a sign of a host
/// around the app.
///
/// @param image_paths The paths of the loaded images, as dyld reports them.
/// @param bundle_directory The main bundle's directory, the one legitimate root outside the system paths, or empty when
/// it could not be read, in which case no image is excused on its account.
/// @return One virt.foreign_images observation read through dyld: the foreign image paths, which is empty when every
/// image lies within a legitimate root.
[[nodiscard]] Observation observe_foreign_images(std::span<const std::string> image_paths,
                                                 std::string_view bundle_directory);

}  // namespace rasp::ios::checks
