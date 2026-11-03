/// The Android hooking checks: whether an instrumentation or hooking framework has mapped foreign code into the app's
/// process, started threads in it, or left memory that is both writable and executable.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the hooking checks and returns what they observed.
///
/// It reads the process's memory map once and reports two things from it: the mappings that look like a known
/// instrumentation framework (Frida, Substrate, Xposed and the like), and the mappings that are both writable and
/// executable. Instrumentation loads its own code into the app's process and often leaves writable-executable memory
/// where it writes the code it runs, so both are signs of hooking that don't depend on the framework's name. The check
/// reports the raw lines; the server decides.
///
/// On Android, the emulator included, it runs the probe. Anywhere else, such as on a Linux host, every observation is
/// unsupported instead, so the server still sees that the check ran.
///
/// It also reads the name of every thread of the process, and reports the threads named like those Frida's agent
/// starts.
///
/// @return One observation per signal and source, in this order: hook.maps_hits then hook.rwx_regions, both read
/// through proc_maps, then hook.threads, read through proc_task.
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

/// Reports the threads, among those listed in `task_path`, whose name contains a marker of Frida's agent:
/// `gum-js-loop` or `frida`, ignoring case.
///
/// `task_path` holds one folder per thread, and each folder holds the thread's name in its `comm` file. A thread whose
/// name can't be read, such as one that ended after the folder was listed, is left out. At most 4096 threads are looked
/// at, and at most 32 names reported.
///
/// @param task_path The folder of the process's threads, `/proc/self/task` on a device.
/// @return One hook.threads observation read through proc_task: the names found, sorted and without duplicates. It has
/// an error status when the folder can't be listed.
[[nodiscard]] Observation observe_threads(std::string_view task_path);

}  // namespace rasp::android::checks
