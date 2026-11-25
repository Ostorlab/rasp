/// at_rest_guard: the load-time proof that the at-rest layer works in the shipped framework.
///
/// RaspRuntime carries an encrypted guard blob in a `__DATA` section the packer fills. At load the runtime reconstructs
/// the seed, hashes its own code, derives the key, and decrypts the blob. When the runtime is intact the blob decrypts
/// to a known marker; when it is patched or the seed is wrong, it does not. This is the smallest end-to-end exercise of
/// the at-rest coupling that runs inside a real framework on a device, without yet encrypting a slice of the host app
/// (which requires the packer to rewrite the app binary and to coexist with app code-signing).
///
/// The guard does not itself react; it returns whether the blob decrypted. The caller decides what an intact or broken
/// guard means, so this stays a pure, testable step.

#pragma once

#include <cstdint>

namespace rasp::ios::selfdecrypt {

/// The result of checking the at-rest guard.
enum class GuardStatus : std::uint8_t {
  /// No packer wrote the guard blob (it is still the default zeros): an unpacked or development build. Not a tamper.
  kAbsent,
  /// The blob is present and decrypted to the marker: the runtime is intact and the key is right.
  kIntact,
  /// The blob is present but did not decrypt to the marker: the key is wrong, which a patched runtime produces.
  kTampered,
};

/// Decrypts the embedded guard blob and reports what it found.
///
/// Distinguishing kAbsent from kTampered lets the caller gate on tamper without breaking an unpacked build: only a
/// present-but-wrong blob (kTampered) means the runtime's code or seed changed after the packer wrote it.
///
/// @return kAbsent when no blob was written, kIntact when it decrypts to the marker, kTampered when a written blob does
/// not.
[[nodiscard]] GuardStatus at_rest_guard_status();

}  // namespace rasp::ios::selfdecrypt
