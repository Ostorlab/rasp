/// Bounded own-process mount context, never a root or kernel-worker verdict.
#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {
/// Parses the complete mountinfo grammar into aggregate context without exporting paths.
/// @param table Complete kernel mountinfo text, bounded to 1MiB and 4096 rows.
/// @return Counts and root read-write context, or error on malformed/over-limit input.
[[nodiscard]] Observation observe_mountinfo(std::string_view table);
/// Reads only a regular descriptor, rejecting final symlinks, FIFO and changing regular files.
/// @param path This process's mountinfo, or a fixture file.
/// @return Aggregate context or error; no partial success.
[[nodiscard]] Observation observe_mountinfo_file(std::string_view path);
/// Reads this process's namespace link with a strict bounded mnt:[decimal] grammar.
/// @param path This process's mount namespace link, or a fixture link.
/// @return The local namespace identity, or error; never comparison with other processes.
[[nodiscard]] Observation observe_mount_namespace(std::string_view path);
/// Runs both own-process context reads on Android, unsupported elsewhere.
/// @return Exactly two independently available observations.
[[nodiscard]] std::vector<Observation> root_context();
}  // namespace rasp::android::checks
