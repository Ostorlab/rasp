/// The Android debugger checks: whether a native debugger or a Java debugger is attached to the app's process.

#pragma once

#include <optional>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the debugger checks and returns what they observed.
///
/// On Android, the emulator included, it runs every probe. Anywhere else, such as on a Linux host, every observation
/// is unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: dbg.tracer_pid through proc_status and through
/// proc_status_syscall, then dbg.java_debugger through is_debugger_connected.
[[nodiscard]] std::vector<Observation> debugger();

/// Reports the process id of the debugger attached to the app, from the status file at `status_path`, read through two
/// sources.
///
/// A native debugger, such as lldb, gdb or strace, attaches with ptrace, and the kernel then shows the debugger's
/// process id on the file's `TracerPid:` line. The line holds 0 when nothing is attached. A Java debugger attaches
/// through JDWP instead, without ptrace, so this probe doesn't see it. The file is read whole, up to 64 KiB, once
/// through the libc file functions and once through direct system calls. A hook on libc that hides the debugger then
/// makes the two values disagree.
///
/// @param status_path The status file to read, `/proc/self/status` on a device.
/// @return Two dbg.tracer_pid observations, read through proc_status and then through proc_status_syscall: each one the
/// tracer's process id, 0 when nothing is attached. Each has an error status when its read of the file fails, the file
/// is larger than 64 KiB, has no `TracerPid:` line, or the line doesn't hold a process id.
[[nodiscard]] std::vector<Observation> observe_tracer_pid(std::string_view status_path);

/// Reports whether a Java debugger is connected to the app, from `connected`, the answer of
/// `android.os.Debug.isDebuggerConnected`.
///
/// A Java debugger, such as Android Studio's default one, connects through JDWP, without ptrace, so dbg.tracer_pid
/// doesn't see it. The runtime asks the app's Java VM instead.
///
/// @param connected What `isDebuggerConnected` returned, or nothing when the runtime couldn't ask it.
/// @return One dbg.java_debugger observation through is_debugger_connected: true when a debugger is connected, false
/// when none is. It has an error status when `connected` is empty.
[[nodiscard]] Observation observe_java_debugger(std::optional<bool> connected);

}  // namespace rasp::android::checks
