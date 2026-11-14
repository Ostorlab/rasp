/// end_process: the exit_group system call, made with the system call instruction of each Android ABI.

#include "panic/end_process.h"

namespace rasp::android {

namespace {

/// The exit status the process ends with.
constexpr long kExitStatus = 0;

#ifdef __aarch64__
/// The number of the exit_group system call on arm64-v8a.
constexpr long kExitGroup = 94;
#elifdef __arm__
/// The number of the exit_group system call on armeabi-v7a.
constexpr long kExitGroup = 248;
#elifdef __x86_64__
/// The number of the exit_group system call on x86_64.
constexpr long kExitGroup = 231;
#elifdef __i386__
/// The number of the exit_group system call on x86.
constexpr long kExitGroup = 252;
#else
#error "end_process has no system call for this ABI"
#endif

/// Makes the exit_group system call once, with kExitStatus. It returns only if the kernel refused the call.
void exit_group() noexcept {
#ifdef __aarch64__
  // NOLINTNEXTLINE(portability-no-assembler): a direct system call leaves no libc function to hook.
  asm volatile("mov x8, %0\n\tmov x0, %1\n\tsvc #0" : : "r"(kExitGroup), "r"(kExitStatus) : "x0", "x8", "memory");
#elifdef __arm__
  // NOLINTNEXTLINE(portability-no-assembler): a direct system call leaves no libc function to hook.
  asm volatile("mov ip, r7\n\tmov r0, %1\n\tmov r7, %0\n\tsvc #0\n\tmov r7, ip"
               :
               : "r"(kExitGroup), "r"(kExitStatus)
               : "r0", "ip", "memory");
#elifdef __x86_64__
  // NOLINTNEXTLINE(portability-no-assembler): a direct system call leaves no libc function to hook.
  asm volatile("mov %1, %%rdi\n\tmov %0, %%rax\n\tsyscall"
               :
               : "r"(kExitGroup), "r"(kExitStatus)
               : "rax", "rdi", "rcx", "r11", "memory");
#elifdef __i386__
  // NOLINTNEXTLINE(portability-no-assembler): a direct system call leaves no libc function to hook.
  asm volatile("mov %1, %%ebx\n\tmov %0, %%eax\n\tint $0x80"
               :
               : "r"(kExitGroup), "r"(kExitStatus)
               : "eax", "ebx", "memory");
#endif
}

}  // namespace

void end_process() noexcept {
  while (true) {
    exit_group();
  }
}

}  // namespace rasp::android
