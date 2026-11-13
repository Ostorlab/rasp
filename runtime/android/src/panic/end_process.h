/// end_process: ends the app's process at once, through a system call made directly.

#pragma once

namespace rasp::android {

/// Ends every thread of the process at once, with exit status 0, and never returns.
///
/// It makes the exit_group system call itself, with the system call instruction of the ABI it is built for
/// (arm64-v8a, armeabi-v7a, x86_64 or x86), without calling any function of libc. No exit handler runs, nothing is
/// flushed, and the system shows no crash dialog. It is how the runtime ends the app after a detection.
[[noreturn]] void end_process() noexcept;

}  // namespace rasp::android
