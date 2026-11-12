/// The Android debugger checks: whether a native or a Java debugger is attached to the app's process.

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
/// @return One observation per signal and source, in this order: dbg.tracer_pid through proc_status, then
/// dbg.java_debugger through jdwp_threads, then dbg.java_debugger through debug_api.
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
[[nodiscard]] std::vector<Observation> observe_tracer_pid(std::string_view status_path);

/// Reports the names of the app's threads that belong to JDWP, the connection of a Java debugger, from the thread
/// folder at `task_path`.
///
/// A Java debugger, such as Android Studio's default one or jdb, attaches through JDWP, without ptrace. ART names the
/// threads of that connection, and the kernel keeps the first 15 bytes of each name. `ADB-JDWP Connec` runs while the
/// app can be debugged. `JDWP Transport ` and `JDWP Event Help` start when a debugger attaches and stay after it
/// detaches, and `JDWP Command Re` runs only while it is attached. Each thread's name is read from
/// `<task_path>/<thread id>/comm`, up to 64 bytes. A thread that ends before its name is read is skipped.
///
/// @param task_path The folder of the app's threads, `/proc/self/task` on a device.
/// @return One dbg.java_debugger observation through jdwp_threads: the thread names that start with `JDWP` or
/// `ADB-JDWP`, sorted and without duplicates, the 16 smallest when there are more. It is empty when the app can't be
/// debugged. It has an error status when the folder can't be read, or holds more than 4096 threads.
[[nodiscard]] Observation observe_jdwp_threads(std::string_view task_path);

/// Reports whether ART says a Java debugger is connected, as `android.os.Debug.isDebuggerConnected` returns it.
///
/// It is a second source for dbg.java_debugger, read through Java rather than the thread folder, so a tool that hides
/// one of the two makes them disagree. `debugger` calls the method through JNI on the runtime's own thread.
///
/// @param connected What the method returned, or nothing when it couldn't be called or threw.
/// @return One dbg.java_debugger observation through debug_api: whether a debugger is connected. It has an error status
/// when `connected` is nothing.
[[nodiscard]] Observation observe_debug_api(std::optional<bool> connected);

}  // namespace rasp::android::checks
