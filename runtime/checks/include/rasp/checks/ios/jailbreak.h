#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::checks::ios {

/// Runs the jailbreak checks. On anything but a physical iOS device, every observation is
/// unsupported: a simulator or a Mac has no sandbox, so the checks would only report noise.
[[nodiscard]] std::vector<Observation> jailbreak();

/// jb.fs_paths, read through two sources, access and stat: the paths of `paths` each one finds.
/// A hook that hides a file from one source and not the other makes the two disagree.
[[nodiscard]] std::vector<Observation> observe_paths(std::span<const std::string_view> paths);

/// jb.sandbox_escape: whether the app can create a file at `probe_path`, outside its sandbox.
[[nodiscard]] Observation observe_sandbox_write(std::string_view probe_path);

/// jb.fork_ok: whether the app can start a child process, which the sandbox forbids.
[[nodiscard]] Observation observe_fork();

}  // namespace rasp::checks::ios
