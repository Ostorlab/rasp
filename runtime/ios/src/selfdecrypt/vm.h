/// The guard VM: a tiny interpreter that runs the at-rest guard's decision as byte-code instead of native code.
///
/// Why a VM. The at-rest coupling (binding the key to the runtime's own `__TEXT,__text`) already makes a patched
/// runtime derive the wrong key, so a guarded region does not decrypt. What stayed native, and therefore patchable, was
/// the decision built on top of it: "did the blob decrypt to the marker? if not, end the process." That was a plain
/// branch an attacker could NOP. Moving it into byte-code removes the native branch: the kill is an opcode (OpCode::
/// kKill) the program jumps to, not a `bl _end_process` sitting next to a `cmp`. And because the interpreter's own code
/// lives in `__TEXT,__text`, which the key is bound to, patching the interpreter to skip the kill changes the hash and
/// the derived key, so the guarded blob no longer decrypts. The attacker cannot cleanly remove the decision without
/// breaking the thing the decision protects.
///
/// Scope and honest limits. This is a fixed-encoding VM for one short program; it raises the cost of a clean patch, it
/// is not a wall. An attacker can still hook `end_process` at the symbol level (the inline-hook check and the covered
/// hash are what answer that), and a time-of-check/time-of-use attacker who lets the genuine program run once can still
/// snapshot the plaintext. The real anchor for those remains off-device attestation. What the VM buys is that the
/// one-instruction "NOP the guard" patch no longer exists.

#pragma once

#include <cstdint>
#include <span>

#include "selfdecrypt/guard.h"

namespace rasp::ios::selfdecrypt {

/// Runs a guard program over the embedded guard blob and reports the guard status it reaches.
///
/// The program drives the native guard steps (derive key, decrypt blob, check marker) and takes the tamper branch,
/// which ends the process, when the marker does not come back. It is the virtualized form of what at_rest_guard_status
/// did as native code; the caller (enforce_at_rest_guard) runs it and does not itself branch on the result.
///
/// The program and the blob are read from the binary. An unpacked build carries no program and a zero blob; the
/// interpreter reports kAbsent for it and never ends the process, so an unpacked or development build still runs.
///
/// @param program The byte-code of the guard program: the opcodes of vm_ops.h, as the packer emitted them.
/// @param program_size The number of bytes in `program`.
/// @return kAbsent when no guard was written, kIntact when the blob decrypted to the marker, kTampered when a written
/// guard did not decrypt (on that path the program ends the process before returning in a packed build).
[[nodiscard]] GuardStatus run_guard_program(const unsigned char* program, unsigned long program_size);

/// Runs a guard program over a caller-provided blob, instead of the one embedded in the binary.
///
/// This is the interpreter proper; run_guard_program is this called with the embedded guard blob. It is exposed so the
/// interpreter's dispatch -- the jumps, the kill opcode, the status the program builds -- can be exercised over a blob
/// a host test controls, which the embedded (zero on an unpacked host build) blob does not allow. Production code calls
/// run_guard_program; only tests call this.
///
/// @param program The byte-code of the guard program.
/// @param program_size The number of bytes in `program`.
/// @param blob The blob the program decrypts and inspects; treated as present even when all zero.
/// @return The guard status the program reaches. On the kill path end_process is called and does not return.
[[nodiscard]] GuardStatus run_guard_program_on_blob(const unsigned char* program, unsigned long program_size,
                                                    std::span<const std::uint8_t> blob);

}  // namespace rasp::ios::selfdecrypt
