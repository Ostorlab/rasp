# Android inline entry-byte observations

Selecting the existing `hooks` check adds one `hook.inline` / `prologue` observation after the existing map and thread observations. No new configuration key, packer format, API field, plugin interface or enforcement action is introduced. The existing map sources remain independent, including disagreements and one-sided failures.

The Android dispatcher resolves 27 libc names and five libdl names through already-loaded library handles (`RTLD_NOLOAD`). Lookup follows the handle's dynamic-linker scope rather than the global default scope; this avoids treating ordinary global interposition as an entry-byte change. A definition resolved from a dependency is checked against the file actually mapped at its address.

| Library handle | Watched names, in output order |
| --- | --- |
| `libc.so` | `open`, `openat`, `read`, `fopen`, `fread`, `access`, `faccessat`, `stat`, `lstat`, `fstat`, `fstatat`, `readlink`, `opendir`, `readdir`, `syscall`, `ptrace`, `fork`, `kill`, `exit`, `_exit`, `abort`, `pthread_create`, `mmap`, `connect`, `__system_property_get`, `__system_property_find`, `__system_property_read_callback` |
| `libdl.so` | `dlopen`, `android_dlopen_ext`, `dlsym`, `dladdr`, `dl_iterate_phdr` |

For every resolved address the collector:

1. Reads a complete `/proc/self/maps` snapshot, limited to 4 MiB with at most 8192 bytes per line. Every record is validated before lookup, including unrelated records. Overlapping candidate mappings fail. Only readable, executable, non-writable file mappings qualify.
2. Reads the mapped library, at most 32 MiB, and validates little-endian ELF32/ELF64 header-table bounds. Production requires its native ARM, AArch64, i386 or x86_64 machine and matching ELF class. The helper also permits inspecting cross-ABI fixtures as data when no native machine is supplied.
3. Finds a unique defined `STT_FUNC` dynamic symbol, with a valid non-reserved section index and nonzero size. The dynamic symbol table must be unique, complete, linked to a bounded string table and contain at most 65536 entries. Lookup reads only the requested name length plus its terminator. Missing/duplicate symbols, IFUNCs and stripped section tables cannot supply a comparison.
4. Translates the symbol's virtual address through an executable, non-writable `PT_LOAD` segment into a bounded file offset. The whole symbol must fit in the segment's file-backed range and the file. That offset must equal mapping file offset plus address displacement, with overflow checks. This accounts for virtual/file offsets and ASLR without assuming the load bias is the map start. ARM Thumb bits are removed from both addresses; top-byte tags are accepted only for AArch64.
5. Rejects loader-declared text relocations (`DT_TEXTREL` or `DF_TEXTREL`) and missing, duplicate or malformed dynamic sections (at most 65536 entries). Ordinary GOT/data relocations and PC-relative PLT calls retain their on-disk code bytes. Compares `min(16, st_size)` bytes. All requested bytes must fit the mapping and be returned by the own-process OS read (`process_vm_readv` on Android/Linux); no maps-derived pointer is dereferenced. Denied, short or stale-memory reads fail safely. The macOS host-test transport uses `mach_vm_read_overwrite`.

The dispatcher always emits these five observations in order:

| Signal | Source | Value on OK |
| --- | --- | --- |
| `hook.maps_hits` | `proc_maps` | Up to 32 raw matching map lines |
| `hook.rwx_regions` | `proc_maps` | Up to 32 raw RWX map lines |
| `hook.maps_hits` | `proc_maps_syscall` | Up to 32 independently read matching map lines |
| `hook.threads` | `proc_task` | Up to 32 sorted distinct matching thread names |
| `hook.inline` | `prologue` | Up to 32 distinct changed function names, in the fixed order above |

`hook.inline` has `kOk` only after every watched function was compared; an empty list means those particular entry bytes matched. Any unavailable library/symbol, failed resolution/close, unsupported file layout, malformed input, size limit or failed/incomplete comparison yields `kError` with no value. It never returns a partially clean list. The reusable collector accepts one to 64 distinct names of 1–128 bytes without NUL, so its maximum result is 64; the dispatcher uses exactly 32. Off Android all five observations are `kUnsupported` with no value. An Android build for an unimplemented architecture also makes the inline observation unsupported. An actual read failure on a supported architecture is an error, not unsupported or an empty clean result.

These are client observations, not attestation or a malware verdict. Authorized instrumentation, profiling, hot patches or rebinding that rewrites a watched entry can produce the same changed bytes as an unauthorized hook. Ordinary interposition or GOT rebinding is outside this entry-byte comparison, and JIT code elsewhere has no effect on it. No process is terminated and no process-wide signal handlers or settings are changed.

The check misses changes after the compared prefix, other inline sites, unlisted or renamed hook targets, hidden modules/mappings, and changes made after the snapshot. An attacker who changes both disk and memory can provide a matching baseline. The filesystem, dynamic linker, memory-read API and libc syscall entry remain hookable. Maps, files and memory are not an atomic snapshot; concurrent remapping or authorized code changes can invalidate coverage. Source disagreement is preserved for the consumer to interpret.

Host tests use real NDK-built ARM64, ARM, Thumb, x86 and x86_64 ELF fixtures mapped RX, stock controls and controlled private memory patches. Cross-ABI bytes are inspected, not executed. A Linux test also loads fixture libraries with the actual watched names and exercises the unchanged Android dispatcher, collector and plugin callback before, during and after a controlled patch. One watched fixture entry calls an imported function through a real loader-relocated PLT/GOT slot, providing a legitimate relocation control. Protected/unreadable pages, short OS reads, malformed maps/ELF/symbol/string metadata, text-relocation flags and bounds are covered. These tests do not establish exhaustive hook detection or efficacy on a physical Android device. Native iOS inline hooking is not implemented here.
