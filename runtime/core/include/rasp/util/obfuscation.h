/// anchor_literals, which keeps string literals where the release string obfuscator can encrypt them.

#pragma once

#include <span>
#include <string_view>

namespace rasp::util {

/// Keeps each literal in `literals` reachable as a real pointer, so the release string obfuscator encrypts it.
///
/// A release build obfuscates the runtime with O-MVLL, whose string pass encrypts the characters behind every string
/// literal it finds. It finds a literal only where the code uses the literal's address as a real pointer at run time. A
/// plain `constexpr std::string_view k = "..."` does not qualify: the compiler folds it into each use as a pair of
/// integers, a form the pass does not recognise, so the text would stay in clear in the shipped library. Listing such
/// literals in a `constexpr std::array` and passing it here keeps each address a real pointer the pass encrypts. The
/// function reads the addresses, never the characters, so it costs nothing in a build that is not obfuscated.
///
/// @param literals The string literals to keep encryptable.
[[gnu::always_inline]] inline void anchor_literals(std::span<const std::string_view> literals) {
  for (const std::string_view literal : literals) {
    const char* volatile address = literal.data();
    static_cast<void>(address);
  }
}

}  // namespace rasp::util
