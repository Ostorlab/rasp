/// end_process: the exit system call, made with the arm64 system call instruction.

#include "panic/end_process.h"

namespace rasp::ios {

namespace {

/// The number of the exit system call, `SYS_exit`, which ends the whole process on XNU.
constexpr long kSysExit = 1;
/// The exit status the process ends with.
constexpr long kExitStatus = 0;

/// Makes the exit system call once, with kExitStatus. It returns only if the kernel refused the call.
void exit_process() noexcept {
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

}  // namespace

void end_process() noexcept {
  while (true) {
    exit_process();
  }
}

}  // namespace rasp::ios
