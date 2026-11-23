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

namespace rasp::ios::selfdecrypt {

/// Decrypts the embedded guard blob and reports whether it decrypted to the expected marker.
///
/// @return true when the runtime is intact and the seed is correct, so the blob decrypts to the marker; false when the
/// blob is still the default (no packer wrote it), the key is wrong (a patched runtime), or the marker does not match.
[[nodiscard]] bool at_rest_guard_intact();

}  // namespace rasp::ios::selfdecrypt
