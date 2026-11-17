/// end_process: ends the process through more than one independent primitive, so neutralising any single
/// one of them does not keep the process alive. A direct exit system call is tried first, then a breakpoint
/// trap, in a loop that never returns.

#include "panic/end_process.h"

namespace rasp::ios {

namespace {

/// The number of the exit system call, `SYS_exit`, which ends the whole process on XNU.
constexpr long kSysExit = 1;
/// The exit status the process ends with.
constexpr long kExitStatus = 0;

/// Makes the exit system call with kExitStatus. A direct system call leaves no libSystem function to hook.
/// It returns only if its instruction was tampered with, such as patched out.
[[gnu::noinline]] void exit_via_syscall() noexcept {
#ifdef __aarch64__
  // NOLINTNEXTLINE(portability-no-assembler): a direct system call leaves no libSystem function to hook.
  asm volatile("mov x16, %0\n\tmov x0, %1\n\tsvc #0x80"
               :
               : "r"(kSysExit), "r"(kExitStatus)
               : "x0", "x16", "memory", "cc");
#else
#error "end_process has no system call instruction for this architecture"
#endif
}

/// Raises a breakpoint exception. It is a different instruction from the exit system call, so an attacker
/// who patches the exit out still has to find and defeat this one as well. It returns only if it too was
/// tampered with.
[[gnu::noinline]] void trap_process() noexcept {
#ifdef __aarch64__
  // NOLINTNEXTLINE(portability-no-assembler): a trap instruction leaves no libSystem function to hook.
  asm volatile("brk #0x7261" : : : "memory");
#else
#error "end_process has no trap instruction for this architecture"
#endif
}

}  // namespace

void end_process() noexcept {
  // Each primitive ends the process on its own; the loop retries the others whenever one is neutralised,
  // so no single patch disables termination and the function never returns.
  while (true) {
    exit_via_syscall();
    trap_process();
  }
}

}  // namespace rasp::ios
