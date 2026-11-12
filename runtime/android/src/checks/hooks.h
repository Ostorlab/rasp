/// The Android hooking checks: whether an instrumentation or hooking framework has mapped foreign code into the app's
/// process, started threads in it, left memory that is both writable and executable, or rewritten the first
/// instructions of a system library function.

#pragma once

#include <cstdint>
#include <span>
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
/// Last, it compares the first bytes of a fixed list of libc and libdl functions in memory with the same bytes in the
/// library files, as observe_inline_hooks describes. The list holds the functions the runtime's checks call and those
/// bypass scripts hook, such as `open`, `access`, `stat`, `syscall`, `ptrace`, `fork`, `kill`, `exit`, `dlopen` and
/// `dlsym`. Each is resolved through its own library's handle, so the address compared is the library's own
/// definition or a definition in its dependency scope rather than the global default scope.
///
/// @return One observation per signal and source, in this order: hook.maps_hits then hook.rwx_regions, both read
/// through proc_maps, then hook.maps_hits through proc_maps_syscall, then hook.threads through proc_task,
/// then hook.inline through prologue. An incomplete comparison reports an error.
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
/// a marker beyond the kernel's truncation point is invisible. Only numeric thread-ID entries count toward the
/// 4096-thread limit or have their comm read. The result contains the lexicographically smallest 32 distinct matching
/// names; reaching the output cap does not stop enumeration.
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

/// A function whose first bytes observe_inline_hooks compares: its name, and the address the dynamic linker resolved it
/// to in this process.
struct ResolvedFunction {
  /// The function's name, as its library exports it, such as `open`.
  std::string_view name;
  /// The address the dynamic linker resolved the function to.
  std::uintptr_t address = 0;
  /// Expected ELF machine in production; zero lets cross-ABI fixtures inspect any supported machine as data.
  std::uint16_t expected_machine = 0;
};

/// Reports the functions among `functions` whose first bytes in memory differ from the same bytes in their library's
/// file, the sign of an inline hook: Frida's Interceptor, Dobby and Substrate overwrite a function's first instructions
/// in memory with a jump, while the file keeps the original bytes.
///
/// The complete bounded maps snapshot is parsed once per call; every malformed or overlapping record fails before
/// lookup. The unique RX, non-writable mapping gives the file offset of the address. A unique defined STT_FUNC symbol
/// with nonzero size must translate through an immutable executable PT_LOAD to that same offset. At most min(16, symbol
/// size) bytes are read through the OS own-process memory API, never dereferenced directly. A short mapping or OS read
/// fails the comparison. Thumb low bits are removed from both code addresses; only AArch64 accepts top-byte tags.
/// Production resolution requires the native ELF machine. Loader-declared text relocations and IFUNC resolvers are not
/// comparable. Ordinary PLT/GOT data relocation does not rewrite these bytes. This reports differences, including
/// authorized instrumentation, without a malware verdict.
///
/// @param maps_path The complete memory map, /proc/self/maps in production, limited to 4 MiB and 8192 bytes per line.
/// @param functions One to 64 distinct function names, each 1 to 128 bytes without NUL, with resolved addresses.
/// @return One hook.inline/prologue observation: kOk with changed names in input order (empty only after all
/// comparisons succeeded); kError with no value on any missing, unreadable, malformed, ambiguous, oversized or
/// incomparable input. Library files are limited to 32 MiB. The dispatcher emits at most 32 changed names from its
/// fixed libc/libdl list. Off Android the dispatcher emits kUnsupported; an unsupported Android architecture also makes
/// inline unsupported.
[[nodiscard]] Observation observe_inline_hooks(std::string_view maps_path, std::span<const ResolvedFunction> functions);

}  // namespace rasp::android::checks
