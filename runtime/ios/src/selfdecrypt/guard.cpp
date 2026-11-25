/// at_rest_guard: see guard.h. The guard's decision is no longer native code; it is a short byte-code program the guard
/// VM runs (see vm.h). This file locates the program the packer embedded and hands it to the interpreter, keeping the
/// public at_rest_guard_status API unchanged for its callers.

#include "selfdecrypt/guard.h"

#ifdef __APPLE__
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#endif

#include "selfdecrypt/chacha20.h"
#include "selfdecrypt/vm.h"

namespace rasp::ios::selfdecrypt {

namespace {

/// A default guard program, linked into the binary so an unpacked build is a valid Mach-O with the program section
/// present. The packer overwrites this section with the real program (which it emits alongside the encrypted blob);
/// until then it is this fixed sequence. The VM reads kAbsent from the zero blob before the program matters, so the
/// default program is never the thing that decides an unpacked build.
///
/// The sequence (byte offsets in brackets) is: [0] derive key, [1] decrypt blob, [2] check marker, [3..4] if no match
/// jump to the tamper block at 8, [5] set intact, [6..7] jump to halt at 10, [8] set tampered, [9] kill, [10] halt. The
/// packer emits this same shape.
#ifdef __APPLE__
[[gnu::section("__DATA,__rasp_vm"), gnu::used]]
#else
[[gnu::section(".rasp_vm"), gnu::used]]
#endif
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the packer overwrites it, in the binary's file.
volatile unsigned char guard_program[] = {
    0x23,        // [0] kDeriveKey
    0x35,        // [1] kDecryptBlob
    0x47,        // [2] kCheckMarker
    0x7d, 0x08,  // [3] kJumpIfNoMatch -> 8
    0x59,        // [5] kSetIntact
    0x8f, 0x0a,  // [6] kJump -> 10
    0x6b,        // [8] kSetTampered
    0x91,        // [9] kKill
    0x11,        // [10] kHalt
};

/// Reads the embedded guard program the VM runs, from the `__DATA,__rasp_vm` section of this framework.
///
/// On device it returns the live section the packer filled; off Apple it returns the linked default array. The bytes
/// are the same in file and memory, like the blob and `__text`, so the packer writes what the runtime reads.
[[nodiscard]] const unsigned char* program_bytes(unsigned long& size) {
#ifdef __APPLE__
  Dl_info info{};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): take the address of a function of this module.
  if (dladdr(reinterpret_cast<const void*>(&chacha20_xor), &info) == 0 || info.dli_fbase == nullptr) {
    size = 0;
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): dli_fbase is this image's mach_header.
  const auto* header = reinterpret_cast<const mach_header_64*>(info.dli_fbase);
  unsigned long section_size = 0;
  const unsigned char* bytes = getsectiondata(header, "__DATA", "__rasp_vm", &section_size);
  if (bytes == nullptr || section_size == 0) {
    size = 0;
    return nullptr;
  }
  size = section_size;
  return bytes;
#else
  size = sizeof(guard_program);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): the VM reads it; volatile marks it packer-written, not const.
  return const_cast<const unsigned char*>(guard_program);
#endif
}

}  // namespace

GuardStatus at_rest_guard_status() {
  unsigned long size = 0;
  const unsigned char* program = program_bytes(size);
  return run_guard_program(program, size);
}

}  // namespace rasp::ios::selfdecrypt
