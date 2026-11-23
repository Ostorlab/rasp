/// end_process: ends the app's process at once, through more than one independent termination primitive.

#pragma once

namespace rasp::ios {

/// Ends the process at once, every thread of it, and never returns.
///
/// It makes the exit system call itself, with the arm64 system call instruction, without calling any function of
/// libSystem, and falls back to a breakpoint trap when that instruction is tampered with, so that patching out
/// any single primitive does not keep the process alive. No exit handler runs and nothing is flushed. It is how
/// the runtime ends the app after a detection.
[[noreturn]] void end_process() noexcept;

}  // namespace rasp::ios
