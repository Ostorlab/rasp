/// The iOS debugger checks: whether a debugger is attached to the app's process, and which process started it.

#pragma once

#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the debugger checks and returns what they observed.
///
/// On a physical iOS device it runs every probe. Anywhere else, on a simulator, a Mac or a Linux host, every
/// observation is unsupported instead, so the result still shows that the check ran.
///
/// @return One observation per signal and source, in this order: dbg.traced through sysctl, then dbg.parent through
/// getppid.
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

/// Reports the process id of the app's parent process.
///
/// iOS starts an app through `launchd`, whose process id is 1, so an app launched normally has 1 as its parent. An app
/// launched under a debugger, such as from Xcode, has the debugger's server as its parent instead. The probe reports
/// the process id as it is and doesn't judge it. It reads it through getppid, which can't fail, so the observation
/// never has an error status. getppid exists on every POSIX system, so the probe also runs on a Mac or a Linux host.
///
/// @return One dbg.parent observation read through getppid, with the parent's process id as an integer.
[[nodiscard]] Observation observe_parent();

}  // namespace rasp::ios::checks
