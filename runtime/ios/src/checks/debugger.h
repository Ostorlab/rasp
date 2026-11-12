/// The iOS debugger checks: whether a debugger is attached to the app's process, which process started it, and which
/// exceptions the app's task sends to an exception port.

#pragma once

#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the debugger checks and returns what they observed.
///
/// On a physical iOS device it runs every probe. Anywhere else, on a simulator, a Mac or a Linux host, every
/// observation is unsupported instead, so the result still shows that the check ran.
///
/// @return One observation per signal and source, in this order: dbg.traced through sysctl and through sysctl_syscall,
/// dbg.parent through getppid and through sysctl_syscall, then dbg.exception_ports through task_get_exception_ports.
[[nodiscard]] std::vector<Observation> debugger();

/// Reports whether the kernel marks the app's process as traced by a debugger.
///
/// A debugger such as lldb attaches to the process with ptrace, and the kernel then sets the `P_TRACED` flag of the
/// process. The probe reads that flag through sysctl, from the process's own `kinfo_proc` entry. It is read again on
/// every call, so it also sees a debugger that attached after the app started. On a system without these process
/// flags, such as Linux, there is nothing to read.
///
/// @return One dbg.traced observation read through sysctl: true when the flag is set, false when it is not. It has an
/// error status when sysctl fails or doesn't return a whole `kinfo_proc` entry, and the unsupported status on a system
/// without these process flags.
[[nodiscard]] Observation observe_traced();

/// Reports whether the kernel marks the app's process as traced by a debugger, through the sysctl system call made
/// directly.
///
/// It reads the same `P_TRACED` flag as observe_traced, from the same `kinfo_proc` entry, but makes the getpid and
/// sysctl system calls itself, with the `svc` instruction, instead of calling the libc functions. A hook on libc's
/// sysctl or getpid can make these sources disagree. Sequential reads can also differ naturally, and kernel
/// compromise or modification of the native instructions can forge agreement. Only nonsimulator arm64 builds for Apple
/// systems make these calls; elsewhere there is nothing to read.
///
/// @return One dbg.traced observation read through sysctl_syscall: true when the flag is set, false when it is not. It
/// has an error status for a native carry error, invalid PID, nonzero sysctl result or incomplete entry, and the
/// unsupported status on a system other than an Apple one on arm64.
[[nodiscard]] Observation observe_traced_syscall();

/// Reports the process id of the app's parent process.
///
/// iOS starts an app through `launchd`, whose process id is 1, so an app launched normally has 1 as its parent. An app
/// launched under a debugger, such as from Xcode, has the debugger's server as its parent instead. The probe reports
/// the process id as it is and doesn't judge it. It reads it through getppid, which can't fail, so the observation
/// never has an error status. getppid exists on every POSIX system, so the probe also runs on a Mac or a Linux host.
///
/// @return One dbg.parent observation read through getppid, with the parent's process id as an integer.
[[nodiscard]] Observation observe_parent();

/// Reports the process id of the app's parent process, from the process's own `kinfo_proc` entry, through the sysctl
/// system call made directly.
///
/// It reads the parent's process id that the kernel keeps in the entry, with the getpid and sysctl system calls made
/// with the `svc` instruction, as observe_traced_syscall does. A hook on libc's getppid that returns 1, the id of
/// `launchd`, while a debugger started the app then makes observe_parent and this probe disagree. Only arm64 builds for
/// Apple systems make these calls; elsewhere there is nothing to read.
///
/// @return One dbg.parent observation read through sysctl_syscall, with the parent's process id as an integer. It has
/// an error status when a system call fails or sysctl doesn't return a whole `kinfo_proc` entry, and the unsupported
/// status off nonsimulator Apple arm64.
[[nodiscard]] Observation observe_parent_syscall();

/// Reports the exceptions for which the app's task has an exception port set.
///
/// A Mach exception port receives the exceptions of a task, such as a bad memory access or a breakpoint, before the
/// process gets a signal. A debugger such as lldb sets exception ports on the app's task when it attaches. The probe
/// asks the kernel through task_get_exception_ports for the ports behind every exception type in `EXC_MASK_ALL`, and
/// reports the bitwise OR of the `EXC_MASK_*` masks whose port is valid. It reports the mask as it is and doesn't
/// judge it. Crash reporters such as Crashlytics, Sentry and PLCrashReporter also set exception ports, so a non-zero
/// value alone doesn't mean that a debugger is attached. The ports are read again on every call, so the probe also sees
/// a debugger that attached after the app started. On a system without Mach exception ports, such as Linux, there is
/// nothing to read.
///
/// @return One dbg.exception_ports observation read through task_get_exception_ports, with the mask as an integer, 0
/// when no exception type has a port. It has an error status when task_get_exception_ports fails, or when a port right
/// it returns can't be released, and the unsupported status on a system without Mach exception ports.
[[nodiscard]] Observation observe_exception_ports();

}  // namespace rasp::ios::checks
