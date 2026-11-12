/// The Android hooking checks: whether an instrumentation or hooking framework has mapped foreign code into the app's
/// process, started threads in it, or left memory that is both writable and executable.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "util/direct_syscall.h"

namespace rasp::android::checks {

/// Runs the hooking checks and returns what they observed.
///
/// It reads the process's memory map independently through libc file functions and the hookable libc syscall entry: the
/// mappings that look like a known instrumentation framework (Frida, Substrate, Xposed and the like), and the mappings
/// that are both writable and executable. Instrumentation can load code or leave writable-executable memory, and
/// legitimate app code can do the same. The check reports raw heuristic map lines; it does not determine whether the
/// app is instrumented.
///
/// On Android, the emulator included, it runs the probe. Anywhere else, such as on a Linux host, every observation is
/// unsupported instead, so the server still sees that the check ran.
///
/// It also reads a bounded snapshot of the app's visible thread names and reports Frida-specific name matches.
/// Generic gmain and thread-pool names alone are benign controls. Names are raw heuristic evidence, not proof of
/// instrumentation: legitimate names can match, and renaming or hiding threads evades this probe.
///
/// @return One observation per signal and source, in this order: hook.maps_hits then hook.rwx_regions, both read
/// through proc_maps, then hook.maps_hits through proc_maps_syscall, then hook.threads through proc_task.
[[nodiscard]] std::vector<Observation> hooks();

/// Reports the mappings of the memory map at `maps_path` that name a known instrumentation framework, and those that
/// are both writable and executable.
///
/// A line of `/proc/self/maps` is `address perms offset dev inode pathname`. A mapping names a framework when its
/// pathname contains a known marker, such as `frida`, `gadget`, `substrate` or `xposed`; a mapping is
/// writable-executable when its permissions are `rwx`. Each list holds at most its first 32 matching lines, without
/// their line breaks.
///
/// @param maps_path The memory map to read, `/proc/self/maps` on a device.
/// @param invoke The hookable libc syscall boundary used for the independent second read.
/// @return hook.maps_hits and hook.rwx_regions through proc_maps, then hook.maps_hits through proc_maps_syscall.
/// Each source fails independently on unreadable, empty, truncated, malformed or oversized data (4 MiB maximum,
/// 8192 bytes per line). Every line is validated before retaining at most 32 matches; divergence is never hidden.
[[nodiscard]] std::vector<Observation> observe_maps(std::string_view maps_path,
                                                    util::SystemCall invoke = util::libc_syscall);

/// Reports the threads, among those listed in `task_path`, whose name contains a marker of Frida's agent:
/// `gum-js-loop` or `frida`, ignoring case.
///
/// `task_path` holds one folder per thread, each with a `comm` file. A complete read accepts one to fifteen
/// non-control name bytes followed by a newline (at most 16 bytes total). Only these kernel-visible bytes are matched;
/// a marker beyond the kernel's truncation point is invisible. At most 4096 entries are read. The result contains the
/// lexicographically smallest 32 distinct matching names; reaching the output cap does not stop enumeration.
///
/// A listing failure, an entry beyond the task limit, or any unreadable or malformed comm makes the whole observation
/// an error with no value, even if earlier names matched. Disappearance during enumeration, permission denial and
/// other I/O failures all mean incomplete coverage; the stable status contract does not distinguish their causes.
/// Concurrent thread creation, removal or renaming means this is not an atomic or exhaustive process snapshot.
///
/// @param task_path The folder of the process's threads, `/proc/self/task` on a device.
/// @return One hook.threads/proc_task observation: a sorted string list with kOk on a complete bounded read,
/// including an empty list when no visible name matches; kError with no value when coverage is incomplete.
[[nodiscard]] Observation observe_threads(std::string_view task_path);

}  // namespace rasp::android::checks
