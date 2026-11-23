/// The guard VM interpreter: see vm.h. A small dispatch loop over the opcodes of vm_ops.h, holding the state the guard
/// program works on (the derived key, the decrypted blob, the marker-match flag, the running status).

#include "selfdecrypt/vm.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#ifdef __APPLE__
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#endif

#include "panic/end_process.h"
#include "selfdecrypt/atrest.h"
#include "selfdecrypt/chacha20.h"
#include "selfdecrypt/guard.h"
#include "selfdecrypt/seed.h"
#include "selfdecrypt/vm_ops.h"

namespace rasp::ios::selfdecrypt {

namespace {

/// The size of the guard blob the program decrypts, in bytes. Matches the packer's blob size.
constexpr std::size_t kGuardSize = 32;

/// The plaintext marker the blob decrypts to when the runtime is intact.
constexpr std::array<std::uint8_t, 8> kMarker = {0x52, 0x41, 0x53, 0x50, 0x4f, 0x4b, 0x21, 0x21};  // "RASPOK!!"

/// The fixed 16-byte counter and nonce the packer used for the guard blob. Public; the key is the secret.
constexpr std::array<std::uint8_t, kNonceSize> kNonce = {0x00, 0x00, 0x00, 0x00, 0x61, 0x74, 0x72, 0x73,
                                                         0x74, 0x67, 0x75, 0x61, 0x72, 0x64, 0x30, 0x31};

/// The encrypted guard blob, in a `__DATA` section the packer overwrites in the binary file. Zero in an unpacked build.
#ifdef __APPLE__
[[gnu::section("__DATA,__rasp_guard"), gnu::used]]
#else
[[gnu::section(".rasp_guard"), gnu::used]]
#endif
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the packer writes it, in the binary's file.
std::array<volatile std::uint8_t, kGuardSize> guard_blob{};

/// The hash of the runtime's own `__TEXT,__text`, which the guard key is bound to.
///
/// The section's bytes are identical in the shipped file and in memory (ASLR slides where `__text` loads, not what it
/// holds), so the packer hashes the same bytes from the file that the runtime hashes from memory. Because the whole
/// `__text` is covered -- including this interpreter's own compiled code -- a patch to the interpreter, the checks, or
/// any runtime code changes the hash and the derived key, and the guarded blob no longer decrypts.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> own_code_hash() {
#ifdef __APPLE__
  Dl_info info{};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): take the address of a function of this module.
  if (dladdr(reinterpret_cast<const void*>(&chacha20_xor), &info) == 0 || info.dli_fbase == nullptr) {
    return {};
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): dli_fbase is this image's mach_header.
  const auto* header = reinterpret_cast<const mach_header_64*>(info.dli_fbase);
  unsigned long size = 0;
  const std::uint8_t* text = getsectiondata(header, "__TEXT", "__text", &size);
  if (text == nullptr || size == 0) {
    return {};
  }
  return hash_region(std::span<const std::uint8_t>(text, size));
#else
  return {};
#endif
}

/// The machine the guard program runs on: the state the opcodes read and write.
///
/// It holds the derived key, a working copy of the guard blob the program decrypts and inspects, the match flag the
/// marker check sets, and the status the program builds up and the interpreter returns.
struct Machine {
  std::array<std::uint8_t, kKeyBytes> key{};
  std::array<std::uint8_t, kGuardSize> blob{};
  bool marker_matches = false;
  GuardStatus status = GuardStatus::kTampered;
};

/// Reports whether the packer wrote any non-zero byte into the embedded blob. An all-zero blob is an unpacked build.
[[nodiscard]] bool embedded_blob_written() {
  for (std::size_t i = 0; i < kGuardSize; i++) {
    if (guard_blob[i] != 0) {
      return true;
    }
  }
  return false;
}

/// kDeriveKey: reconstruct the seed, hash the runtime's own code, and derive and cache the guard key.
void op_derive_key(Machine& machine) {
  std::array<std::uint8_t, kSeedBytes> seed{};
  reconstruct_seed(seed);
  machine.key = derive_key(own_code_hash(), seed);
}

/// kDecryptBlob: decrypt the working blob in place with the derived key.
void op_decrypt_blob(Machine& machine) {
  chacha20_xor(machine.blob.data(), machine.blob.size(), machine.key.data(), kNonce.data());
}

/// kCheckMarker: set the match flag when the decrypted blob starts with the marker.
void op_check_marker(Machine& machine) {
  bool matches = true;
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    if (machine.blob[i] != kMarker[i]) {
      matches = false;
    }
  }
  machine.marker_matches = matches;
}

}  // namespace

GuardStatus run_guard_program_on_blob(const unsigned char* program, unsigned long program_size,
                                      std::span<const std::uint8_t> blob) {
  Machine machine;
  for (std::size_t i = 0; i < kGuardSize && i < blob.size(); i++) {
    machine.blob[i] = blob[i];
  }
  if (program == nullptr || program_size == 0) {
    return GuardStatus::kTampered;  // a blob was written but the program was stripped: treat as tampered.
  }

  // A corrupt or patched program could jump into a loop; bound the number of steps so the guard never hangs the launch.
  // The guard program is a dozen instructions, so a generous multiple of the program size is never reached legitimately.
  const std::size_t max_steps = (program_size * 8) + 64;
  std::size_t pc = 0;
  std::size_t steps = 0;
  while (pc < program_size) {
    if (steps >= max_steps) {
      return GuardStatus::kTampered;  // ran too long: a looping, corrupt program.
    }
    steps++;
    const auto op = static_cast<OpCode>(program[pc]);
    pc++;
    switch (op) {
      case OpCode::kHalt:
        return machine.status;
      case OpCode::kDeriveKey:
        op_derive_key(machine);
        break;
      case OpCode::kDecryptBlob:
        op_decrypt_blob(machine);
        break;
      case OpCode::kCheckMarker:
        op_check_marker(machine);
        break;
      case OpCode::kSetIntact:
        machine.status = GuardStatus::kIntact;
        break;
      case OpCode::kSetTampered:
        machine.status = GuardStatus::kTampered;
        break;
      case OpCode::kJumpIfNoMatch:
        if (pc >= program_size) {
          return GuardStatus::kTampered;  // truncated operand: a stripped or corrupt program.
        }
        if (machine.marker_matches == false) {
          pc = program[pc];
          break;
        }
        pc++;  // skip the jump target operand.
        break;
      case OpCode::kJump:
        if (pc >= program_size) {
          return GuardStatus::kTampered;
        }
        pc = program[pc];
        break;
      case OpCode::kKill:
        end_process();  // [[noreturn]] on the tamper path in a packed build.
        return GuardStatus::kTampered;
      default:
        return GuardStatus::kTampered;  // an unknown opcode is a corrupt or patched program.
    }
  }
  return machine.status;  // ran off the end without halting: return whatever status was set.
}

GuardStatus run_guard_program(const unsigned char* program, unsigned long program_size) {
  if (embedded_blob_written() == false) {
    return GuardStatus::kAbsent;  // the packer wrote nothing: an unpacked or development build.
  }
  std::array<std::uint8_t, kGuardSize> blob{};
  for (std::size_t i = 0; i < kGuardSize; i++) {
    blob[i] = guard_blob[i];
  }
  return run_guard_program_on_blob(program, program_size, std::span<const std::uint8_t>(blob));
}

}  // namespace rasp::ios::selfdecrypt
