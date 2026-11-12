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
/// @return One observation per signal and source, in this order: dbg.traced through sysctl, dbg.traced through
/// syscall, dbg.parent through getppid, dbg.parent through syscall, then dbg.exception_ports through
/// task_get_exception_ports.
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

/// Reports the same `P_TRACED` flag as observe_traced, read a second way to catch a hook on the libc sysctl.
///
/// The traced flag read through the libc `sysctl` function can be lied to: a hook on `sysctl`, a common debugger
/// bypass, clears the flag before the probe sees it. This probe makes the same `kinfo_proc` request as a direct system
/// call, which that hook never runs, so a hook that hides the flag from one source leaves the two sources disagreeing.
/// A hook on the `syscall` wrapper itself would still catch both, but that is a rarer and more invasive hook than one
/// on `sysctl`.
///
/// @return One dbg.traced observation read through syscall: true when the flag is set, false when it is not. It has an
/// error status when the system call fails or doesn't return a whole `kinfo_proc` entry, and the unsupported status on
/// a system without these process flags.
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

/// Reports the same parent process id as observe_parent, read a second way to catch a hook on getppid.
///
/// The parent id read through the libc `getppid` function can be lied to: a hook on `getppid` returns 1, the id of
/// `launchd`, while a debugger started the app. This probe reads the parent id from the process's own `kinfo_proc`
/// entry as a direct `sysctl` system call instead, which neither a hook on `getppid` nor a hook on the libc `sysctl`
/// ever runs, so a hook that reports 1 from one source leaves the two sources disagreeing.
///
/// @return One dbg.parent observation read through syscall, with the parent's process id as an integer. It has an error
/// status when the system call fails or doesn't return a whole `kinfo_proc` entry, and the unsupported status on a
/// system without these process entries.
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
