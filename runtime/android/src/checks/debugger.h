/// The Android debugger checks: whether a native debugger is attached to the app's process.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the debugger checks and returns what they observed.
///
/// On Android, the emulator included, it runs every probe. Anywhere else, such as on a Linux host, every observation
/// is unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: dbg.tracer_pid through proc_status.
[[nodiscard]] std::vector<Observation> debugger();

/// Reports the process id of the debugger attached to the app, from the status file at `status_path`.
///
/// A native debugger, such as lldb, gdb or strace, attaches with ptrace, and the kernel then shows the debugger's
/// process id on the file's `TracerPid:` line. The line holds 0 when nothing is attached. A Java debugger attaches
/// through JDWP instead, without ptrace, so this probe doesn't see it. The file is read whole, up to 64 KiB.
///
/// @param status_path The status file to read, `/proc/self/status` on a device.
/// @return One dbg.tracer_pid observation read through proc_status: the tracer's process id, 0 when nothing is
/// attached. It has an error status when the file can't be read, is larger than 64 KiB, has no `TracerPid:` line,
/// or the line doesn't hold a process id.
[[nodiscard]] Observation observe_tracer_pid(std::string_view status_path);

}  // namespace rasp::android::checks
