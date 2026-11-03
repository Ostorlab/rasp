/// The Android hooking checks: whether an instrumentation or hooking framework has mapped foreign code into the app's
/// process, or left memory that is both writable and executable.

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
/// @return One observation per signal and source, in this order: hook.maps_hits then hook.rwx_regions, both read
/// through proc_maps, then hook.maps_hits read through proc_maps_syscall.
[[nodiscard]] std::vector<Observation> hooks();

/// Reports the mappings of the memory map at `maps_path` that name a known instrumentation framework, and those that
/// are both writable and executable.
///
/// A line of `/proc/self/maps` is `address perms offset dev inode pathname`. A mapping names a framework when its
/// pathname contains a known marker, such as `frida`, `gadget`, `substrate` or `xposed`; a mapping is
/// writable-executable when its permissions are `rwx`. Each list holds at most its first 32 matching lines, without
/// their line breaks. The map is read twice, once through the libc file functions and once through direct system
/// calls, and the framework lines are reported from both reads, so a hook on libc that hides a framework's mapping
/// makes the two sources disagree. The writable-executable lines are reported from the libc read only: a JIT can map
/// or unmap such memory between the two reads, so two honest reads could disagree.
///
/// @param maps_path The memory map to read, `/proc/self/maps` on a device.
/// @return Three observations: hook.maps_hits, the lines that name a framework, then hook.rwx_regions, the
/// writable-executable lines, both read through proc_maps; then hook.maps_hits read through proc_maps_syscall. An
/// observation has an error status when its source can't read the map or the map is larger than 4 MiB.
[[nodiscard]] std::vector<Observation> observe_maps(std::string_view maps_path);

}  // namespace rasp::android::checks
