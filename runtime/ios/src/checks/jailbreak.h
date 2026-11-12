/// The iOS jailbreak checks: whether jailbreak files exist, whether the app can escape its sandbox, and whether it
/// can fork.

#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the jailbreak checks and returns what they observed.
///
/// On a physical iOS device it runs every probe. Anywhere else, on a simulator, a Mac or a Linux host, it cannot: there
/// is no app sandbox there, so the probes would only report noise. There every observation is unsupported instead, so
/// the result still shows that the check ran.
///
/// @return One observation per source: jb.fs_paths read through access and through stat, jb.sandbox_escape through
/// open, and jb.fork_ok through fork.
[[nodiscard]] std::vector<Observation> jailbreak();

/// Reports which of `paths` exist, read through two sources, access and stat.
///
/// Each path is looked up twice. A hook that hides a jailbreak file from one source but not the other makes the two
/// lists disagree; ordinary sequential changes can also do that. ENOENT/ENOTDIR means not found in the caller's
/// view. Other lookup failures invalidate the whole source, without a partial list or proof of stock.
///
/// @param paths The paths to look for, such as the known jailbreak artifact paths.
/// @return Two jb.fs_paths observations: the paths found through access, then the paths found through stat.
[[nodiscard]] std::vector<Observation> observe_paths(std::span<const std::string_view> paths);

/// Reports whether the app can create a file at `probe_path`, a path outside its sandbox.
///
/// Exclusive creation never truncates an existing host file or follows a final symlink. A new probe is removed
/// immediately; close/cleanup failures are error. Historical false means only that this attempted write was refused
/// or its parent was missing (EPERM/EACCES/EROFS/ENOENT). Sealed-volume and policy refusals cannot prove an intact
/// sandbox or absence of jailbreak. Other failures, including an existing path, are error.
///
/// @param probe_path The path to try to create, outside the app's sandbox.
/// @return One jb.sandbox_escape observation read through open: true when the file was created, false when the write
/// was refused, and an error status when the attempt failed for another reason.
[[nodiscard]] Observation observe_sandbox_write(std::string_view probe_path);

/// Reports whether the app can start a child process with fork.
///
/// The iOS sandbox forbids fork, so a child that starts means the sandbox is not in force. A child that does start is
/// reaped at once, so no zombie process is left behind. A refusal the sandbox explains (operation not permitted) is
/// reported as false; any other failure, such as too many processes or too little memory, is reported as an error.
///
/// @return One jb.fork_ok observation read through fork: true when a child process started, false when fork was
/// refused, and an error status when fork failed for another reason.
[[nodiscard]] Observation observe_fork();

}  // namespace rasp::ios::checks
