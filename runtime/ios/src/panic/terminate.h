/// terminate_now: the process-termination primitives, as an always-inlined sequence with no out-of-line symbol.
///
/// The runtime ends a tampered app by welding these instructions directly into each site that decides to end it,
/// rather than calling one named function. An attacker who replaces a single `end_process` symbol, or hooks the
/// function pointer the core panic path calls through, does not reach the copies the compiler inlined at the
/// detection sites: there is no one function to find in `nm`, and no one address for `Interceptor.replace` to take
/// over. Each primitive ends the process on its own; when one is patched out the loop falls through to the next, so
/// defeating termination means defeating every inlined copy of every primitive at once.
///
/// This is an on-device cost-raiser, not an impossibility proof: on a rooted device an attacker can still script a
/// bypass. The point is that the single-function bypass that let a Frida-attached app keep running no longer applies.

#pragma once

namespace rasp::ios {

/// Makes the exit system call with status 0, inline, with the arm64 system call instruction. A direct system call
/// leaves no libSystem function to hook. Returns only if its instruction was tampered with, such as patched to a
/// `ret` or NOP.
[[gnu::always_inline]] inline void terminate_via_syscall() noexcept {
#ifdef __aarch64__
  // SYS_exit is 1 on XNU; it ends the whole process. The literals are loaded as immediates, not read from a hookable
  // data symbol, so there is nothing to interpose.
  // NOLINTNEXTLINE(portability-no-assembler): a direct system call leaves no libSystem function to hook.
  asm volatile("mov x16, #1\n\tmov x0, #0\n\tsvc #0x80" : : : "x0", "x16", "memory", "cc");
#endif
}

/// Raises a breakpoint exception, inline. It is a different instruction from the exit system call, so an attacker who
/// patches the exit out still has to find and defeat this one as well, at every site it was inlined into. Returns only
/// if it too was tampered with.
[[gnu::always_inline]] inline void terminate_via_trap() noexcept {
#ifdef __aarch64__
  // NOLINTNEXTLINE(portability-no-assembler): a trap instruction leaves no libSystem function to hook.
  asm volatile("brk #0x7261" : : : "memory");
#endif
}

/// Ends the process at once, inline, through both primitives in a loop that never returns.
///
/// Because it is always-inlined, every caller gets its own copy of the instructions rather than a call to one shared
/// function. The loop retries the primitives whenever one is neutralised, so no single patch disables termination at
/// a given site, and no single symbol replacement disables it everywhere.
[[noreturn]] [[gnu::always_inline]] inline void terminate_now() noexcept {
  while (true) {
    terminate_via_syscall();
    terminate_via_trap();
  }
}

}  // namespace rasp::ios
