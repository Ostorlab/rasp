/// The opcode set of the guard VM: a tiny byte-code the guard program is written in.
///
/// The at-rest guard's decision -- derive the key from the runtime's own code, decrypt the embedded blob, compare it to
/// the marker, and end the process when it does not match -- is not expressed as native arm64 any more. It is expressed
/// as a short program in these opcodes, which `run_guard_program` interprets. An attacker reading the module no longer
/// finds a native `cmp`/`b.ne`/`bl _end_process` to patch out: the kill is an opcode reached by a byte-code jump, and
/// the whole interpreter sits in `__TEXT,__text`, which the key is bound to, so patching the interpreter changes the
/// hash and the key and the blob no longer decrypts. See vm.h.
///
/// The encoding is fixed in this build (a later build may permute it per release). The opcodes are deliberately few: the
/// program only has to drive the existing native steps in the right order and take one branch.

#pragma once

#include <cstdint>

namespace rasp::ios::selfdecrypt {

/// One byte-code operation. The numeric values are the on-the-wire encoding the packer emits and the interpreter reads;
/// they are an internal contract between vm_assembler.py and run_guard_program, not a public ABI.
enum class OpCode : std::uint8_t {
  /// Stop interpreting and return the current status. One byte.
  kHalt = 0x11,
  /// Reconstruct the seed and hash the runtime's own code, deriving and caching the guard key. One byte.
  kDeriveKey = 0x23,
  /// Decrypt the embedded guard blob in place with the derived key. One byte.
  kDecryptBlob = 0x35,
  /// Compare the first marker-length bytes of the decrypted blob to the marker; set the match flag. One byte.
  kCheckMarker = 0x47,
  /// Set the status to intact. One byte.
  kSetIntact = 0x59,
  /// Set the status to tampered. One byte.
  kSetTampered = 0x6b,
  /// If the match flag is not set, jump to the one-byte absolute program offset that follows. Two bytes.
  kJumpIfNoMatch = 0x7d,
  /// Jump unconditionally to the one-byte absolute program offset that follows. Two bytes.
  kJump = 0x8f,
  /// End the process at once. Reached only on the tamper path. One byte. Does not return.
  kKill = 0x91,
};

}  // namespace rasp::ios::selfdecrypt
