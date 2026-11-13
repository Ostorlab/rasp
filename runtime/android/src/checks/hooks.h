/// The Android hooking checks: whether an instrumentation or hooking framework has mapped foreign code into the app's
/// process, or left memory that is both writable and executable.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the hooking checks and returns what they observed.
///
/// It reads the process's memory map and its thread names, and reports three things: the mappings that look like a
/// known instrumentation framework (Frida, Substrate, Xposed and the like), the mappings that are both writable and
/// executable, and the threads whose names a hooking framework gave them. Instrumentation loads its own code into
/// the app's process and often leaves writable-executable memory where it writes the code it runs; Frida's GUM
/// runtime names its own threads (`gum-js-loop`, `gmain`, `gdbus`, `pool-frida`). The check reports the raw lines
/// and names; the server decides.
///
/// On Android, the emulator included, it runs the probes. Anywhere else, such as on a Linux host, every observation
/// is unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: hook.maps_hits, hook.rwx_regions and hook.threads.
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
/// @return Two observations read through proc_maps: hook.maps_hits, the lines that name a framework, then
/// hook.rwx_regions, the writable-executable lines. Both have an error status when the map can't be read or is larger
/// than 4 MiB.
[[nodiscard]] std::vector<Observation> observe_maps(std::string_view maps_path);

/// Reports the threads of the process whose names a hooking framework gave them, read from the `comm` file of each
/// thread in `task_path`.
///
/// Frida's GUM runtime names its threads `gum-js-loop`, `gmain`, `gdbus` and `pool-frida`; a framework that renames
/// them is caught by its memory mapping instead. A thread name is at most 15 characters on Linux.
///
/// @param task_path The thread list to read, `/proc/self/task` on a device.
/// @return One observation read through proc_task: hook.threads, the framework-named thread names, at most 16 of
/// them, sorted and without duplicates. It has an error status when the thread list can't be read.
[[nodiscard]] std::vector<Observation> observe_threads(std::string_view task_path);

}  // namespace rasp::android::checks
