/// The Android hooking checks: whether an instrumentation or hooking framework has mapped foreign code into the app's
/// process, left memory that is both writable and executable, loaded a library from outside the app, or named its own
/// threads.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"
#include "util/raw_file.h"

namespace rasp::android::checks {

/// Runs the hooking checks and returns what they observed.
///
/// It reads the process's memory map and its thread names, and reports four things: the mappings that look like a
/// known instrumentation framework (Frida, Substrate, Xposed and the like), the mappings that are both writable and
/// executable, the shared libraries loaded from outside the system, vendor and app directories, and the threads whose
/// names a hooking framework gave them. Instrumentation loads its own code into the app's process, often from a
/// temporary folder, and often leaves writable-executable memory where it writes the code it runs; Frida's GUM runtime
/// names its own threads (`gum-js-loop`, `gmain`, `gdbus`, `pool-frida`). The check reports the raw lines and names;
/// the server decides.
///
/// On Android, the emulator included, it runs the probes. Anywhere else, such as on a Linux host, every observation
/// is unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: hook.maps_hits, hook.rwx_regions, hook.foreign_libs
/// and hook.threads.
[[nodiscard]] std::vector<Observation> hooks();

/// Reports the mappings of the memory map at `maps_path` that name a known instrumentation framework, those that are
/// both writable and executable, and the shared libraries mapped from outside the expected directories.
///
/// A line of `/proc/self/maps` is `address perms offset dev inode pathname`. A mapping names a framework when its
/// pathname contains a known marker, such as `frida`, `gadget`, `substrate` or `xposed`; a mapping is
/// writable-executable when its permissions are `rwx`; a mapping is a foreign library when its pathname ends in `.so`
/// and is not under `/system/`, `/apex/`, `/vendor/`, `/product/` or `/data/app/`. A library whose file was deleted
/// after it was mapped, which the map shows with ` (deleted)` after its pathname, counts too. Each list holds at most
/// its first 32 matching lines, without their line breaks.
///
/// @param maps_path The memory map to read, `/proc/self/maps` on a device.
/// @param read The reader the map is read with. The shipped runtime leaves the default, read_proc_file, so an
/// interposed libc function can't answer for the kernel; a test passes read_file to feed a regular file of controlled
/// content.
/// @return Three observations read through proc_maps: hook.maps_hits, the lines that name a framework, then
/// hook.rwx_regions, the writable-executable lines, then hook.foreign_libs, the foreign-library lines. All three have
/// an error status when the map can't be read or is larger than 4 MiB.
[[nodiscard]] std::vector<Observation> observe_maps(std::string_view maps_path,
                                                    rasp::util::ProcReader read = rasp::util::read_proc_file);

/// Reports the threads of the process whose names a hooking framework gave them, read from the `comm` file of each
/// thread in `task_path`.
///
/// Frida's GUM runtime names its threads `gum-js-loop`, `gmain`, `gdbus` and `pool-frida`; a framework that renames
/// them is caught by its memory mapping instead. A thread name is at most 15 characters on Linux.
///
/// A thread that ends while the list is read is left out. The list can't be read whole when it can't be opened, when
/// reading it fails, when it holds more than 4096 threads, or when the name of a thread that is still running can't
/// be read; the observation then has an error status rather than a partial list.
///
/// @param task_path The thread list to read, `/proc/self/task` on a device.
/// @param read The reader each thread's `comm` file is read with. The shipped runtime leaves the default,
/// read_proc_file, so an interposed libc function can't answer for the kernel; a test passes read_file to feed regular
/// files of controlled content.
/// @return One observation read through proc_task: hook.threads, the framework-named thread names, at most 16 of
/// them, sorted and without duplicates. It has an error status when the thread list can't be read whole.
[[nodiscard]] std::vector<Observation> observe_threads(std::string_view task_path,
                                                       rasp::util::ProcReader read = rasp::util::read_proc_file);

}  // namespace rasp::android::checks
