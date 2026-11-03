/// The Android hooking checks: whether an instrumentation or hooking framework has mapped foreign code into the app's
/// process, started threads in it, left memory that is both writable and executable, or rewritten the first
/// instructions of a system library function.

#pragma once

#include <cstdint>
#include <span>
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
/// Last, it compares the first bytes of a fixed list of libc and libdl functions in memory with the same bytes in the
/// library files, as observe_inline_hooks describes. The list holds the functions the runtime's checks call and those
/// bypass scripts hook, such as `open`, `access`, `stat`, `syscall`, `ptrace`, `fork`, `kill`, `exit`, `dlopen` and
/// `dlsym`. Each is resolved through its own library's handle, so the address compared is the library's own
/// definition even when another library interposes the same name.
///
/// @return One observation per signal and source, in this order: hook.maps_hits then hook.rwx_regions, both read
/// through proc_maps, then hook.threads, read through proc_task, then hook.inline, read through prologue. hook.inline
/// has an error status when libc or libdl isn't loaded or doesn't export one of the listed functions, and in the cases
/// observe_inline_hooks lists.
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

/// A function whose first bytes observe_inline_hooks compares: its name, and the address the dynamic linker resolved it
/// to in this process.
struct ResolvedFunction {
  /// The function's name, as its library exports it, such as `open`.
  std::string_view name;
  /// The address the dynamic linker resolved the function to.
  std::uintptr_t address = 0;
};

/// Reports the functions among `functions` whose first bytes in memory differ from the same bytes in their library's
/// file, the sign of an inline hook: Frida's Interceptor, Dobby and Substrate overwrite a function's first instructions
/// in memory with a jump, while the file keeps the original bytes.
///
/// For each function, the mapping of `maps_path` that holds its address gives the library's file and the file offset
/// the address is mapped from. The function's name is looked up in that file's dynamic symbol table, and the symbol's
/// address is translated through the file's program headers to a file offset inside an executable, non-writable
/// segment. When the two offsets agree, the first 16 bytes of the function in memory are compared with the 16 bytes at
/// that offset in the file, fewer when the segment's file part or the mapping ends sooner. An address is looked up
/// without its top byte, and on 32-bit Arm without its Thumb bit.
///
/// @param maps_path The memory map to read, `/proc/self/maps` on a device.
/// @param functions The functions to compare, at most 64.
/// @return One hook.inline observation read through prologue: the names of the functions whose bytes differ, in the
/// order of `functions`. It has an error status when the map can't be read or is larger than 4 MiB, when there are
/// more than 64 functions, or when any function can't be compared: its address isn't in a readable, executable mapping
/// of a file; the file can't be read, is larger than 32 MiB or isn't an ELF file; the file defines no function of that
/// name whose code lies in an executable, non-writable segment; or the symbol's file offset and the mapped address's
/// file offset differ.
[[nodiscard]] Observation observe_inline_hooks(std::string_view maps_path, std::span<const ResolvedFunction> functions);

}  // namespace rasp::android::checks
