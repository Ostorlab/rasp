/// end_process: ends the app's process at once, through a system call made directly.

#pragma once

namespace rasp::ios {

/// Ends the process at once, every thread of it, with exit status 0, and never returns.
///
/// It makes the exit system call itself, with the arm64 system call instruction, without calling any function of
/// libSystem. No exit handler runs and nothing is flushed. It is the end step of a panic that panic_on_detection armed.
[[noreturn]] void end_process() noexcept;

}  // namespace rasp::ios
