# Second-source observation contracts

These checks emit raw `signal/source/status/value` observations. The monitoring thread selects debugger, hooks
and root groups from config and passes every returned observation to `plugins::run_plugins`. No local comparison,
threat verdict or enforcement is added. Sequential reads are not atomic: a debugger attach, process change or
mount change can produce legitimate divergence. Hooked user-space and compromised kernel sources can also agree.

| Platform/group | Signal | Sources, in emitted order | Successful value |
| --- | --- | --- | --- |
| Android/debugger | `dbg.tracer_pid` | `proc_status`, `proc_status_syscall` | Nonnegative integer PID; zero if no tracer visible |
| Android/debugger | `dbg.java_debugger` | `jdwp_threads`, `debug_api` | Existing name list, then JNI boolean |
| Android/hooks | `hook.maps_hits` | `proc_maps`, `proc_maps_syscall` | First 32 marker-matching map lines |
| Android/hooks | `hook.rwx_regions` | `proc_maps` | First 32 writable/executable map lines |
| Android/hooks | `hook.threads` | `proc_task` | Existing RT03 sorted/deduplicated visible name list |
| Android/root | `root.fs_paths` | `access`, `stat`, `faccessat_syscall` | Artifact paths found, in candidate order |
| Android/root | `root.mounts`, `root.rw_mounts` | Each pair through `proc_mounts`, then through `proc_mounts_syscall` | First 32 matching mount lines per signal |
| iOS/debugger | `dbg.traced` | `sysctl`, `sysctl_syscall` | Boolean `P_TRACED` flag |
| iOS/debugger | `dbg.parent` | `getppid`, `sysctl_syscall` | Raw parent PID, without judging the parent |
| iOS/debugger | `dbg.exception_ports` | `task_get_exception_ports` | Existing exception mask; crash reporters can set ports |

The complete Android hooks vector is maps hits/libc, RWX/libc, maps hits/syscall, threads. Root continues with the
existing SELinux and property sources. JNI uses the current attached-env/local-frame implementation and retains the
existing `debug_api` name; the superseded PR178 JNI discovery path does not replace it.

Every source keeps its own status/value even if another succeeds or disagrees. `kError` and `kUnsupported` have
no value (monostate), never a guessed zero, false, or empty list. Path lookups return absent only for ENOENT/ENOTDIR;
denial, symlink loops and other errors invalidate the entire affected source. Thus inaccessible `/data/adb` paths
can make `root.fs_paths` unavailable even on stock devices, including when another candidate was found earlier.
Consumers must keep that unknown state, rather than infer either root or a clean device.

## Native and input boundaries

Android second reads call bionic/libc `syscall` for openat/read/close and faccessat; that exported libc entry can
itself be hooked. They are not direct inline assembly or kernel-resistant reads. Reads use O_NONBLOCK/O_CLOEXEC,
retry at most eight interrupted reads, accept short positive reads until EOF, reject counts outside the requested
buffer, and close an acquired descriptor exactly once. Close errors invalidate the result; close is never retried.
An embedded NUL or empty path is rejected, and no caller can request more than 4 MiB. Fixed production paths inspect
only the app's own procfs files and the existing artifact list; there is no new other-process or system scan.

Status reads accept at most 64 KiB, require a final newline and exactly one TracerPid field, and reject negative,
overflowing or malformed PIDs. Maps reads accept at most 4 MiB; mounts at most 1 MiB. Both require nonempty complete
records, validate all records including those after the output cap, and reject lines over 8192 bytes or control bytes.
Maps validate address order, permissions and numeric fields. Mounts validate all six fields. A source with any
truncated/malformed record yields error for all of its observations, without a partial clean list.

RT03 thread bounds and error handling are preserved: 4096 entries, complete visible comm names of 1–15 non-control
bytes plus newline, at most 32 distinct names retained, continued enumeration after the output cap, and whole-source
failure on an incomplete snapshot. Renaming, kernel truncation and hiding remain evasion limits.

The iOS second sources use the inherited Darwin arm64 `svc #0x80` sequence, capture the carry error flag, and query
only the app's own kinfo_proc entry. Platform headers supply SYS_getpid/SYS_sysctl and the native structure; no private
prototype is declared. Before narrowing, the getpid result must be positive and fit signed 32 bits; sysctl must return
zero and exactly the requested structure size. A negative native parent PID is rejected. The assembly is unavailable
off Apple arm64 and on simulators; debugger() reports every source unsupported off a physical iOS device. The existing
public sysctl/getppid/Mach interfaces, iOS12 deployment target and API31 Android minimum are retained.

## Evidence and integration followups

Host tests exercise real file parsing, typed denied/error/short/invalid-count syscall fixtures, source divergence,
compiled Android hooks() dispatch on Linux own-process procfs, and the real plugin callback. The opaque iOS native
transport fixtures exercise PID/carry/result/size checks through the production query helper; they do not execute
Darwin instructions or decode an actual device kinfo_proc. Original PR178 arm64 iOS CI passed, but it does not validate
these final sources. Exact final-head supported LLVM23 and macOS/Xcode iOS release/dev/tidy/artifact CI remains required
after approved publication. Physical stock/rooted/debugged-device calibration remains separate and unperformed here.

Expected-source manifests must be versioned per release/platform/architecture/config. Register the syscall sources
above alongside existing ones; retain unsupported entries on unsupported architectures and do not require successful
reads. Versioned backend assessments must treat error/unsupported/missing as unknown, preserve source provenance and
contradictions, and avoid converting agreement or a single marker into proof of a clean or malicious device. Existing
generic plugin serializers carry these typed observations; this change does not register backend assessment rules,
implement the expected-source manifest, or complete roadmap spoofing/emulator/root-hiding coverage.

Native ABI reference: [Apple XNU syscall definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master)
and [Apple user-side syscall stubs](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/custom/SYS.h).
These source references supplement SDK/CI checks; they do not establish final-head device execution.
