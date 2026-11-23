/// hidden_string: compile-time XOR-masked string literals that do not appear in the binary as plaintext.
///
/// The iOS checks look for known artifacts by their path or name -- jailbreak files, hooking frameworks, simulator
/// machine names. Those literals are passed to system calls (stat/access) and reported to the server, so they must be
/// real, readable strings at the moment they are used. But if they are stored as plain `constexpr` arrays, `strings`
/// on the shipped framework prints the whole "what is checked" map, and O-MVLL's string-encryption pass cannot hide
/// them (they are read as constant data through pointers -- the PR #190 limitation, which is why they are skip-listed).
///
/// A HiddenString stores the bytes XOR-masked at compile time, so the plaintext never appears in the binary. It is
/// revealed to a `std::string` on demand, right before use, so the plaintext exists only briefly on the heap while a
/// probe runs, not statically in the image. This is obfuscation, not encryption: a determined attacker who reads the
/// code dynamically still recovers the strings. It raises the cost of the cheapest attack -- `strings` on the file --
/// from "free" to "read the disassembly".

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rasp::ios::util {

/// The per-byte mask applied to a hidden string's bytes. A fixed compile-time key: this is obfuscation to defeat a
/// static `strings` dump, not a secret. Each byte is also mixed with its index so repeated characters do not produce
/// repeated cipher bytes, which would let the masked array be recognised by its shape.
inline constexpr std::uint8_t kHiddenStringKey = 0x5A;

/// Masks one byte of a hidden string: XOR with the key and the byte's position, so the masking is position-dependent.
///
/// @param value The plaintext (when masking) or cipher (when unmasking) byte.
/// @param index The byte's position in the string.
/// @return The transformed byte. Applying this function twice with the same index returns the original byte.
[[nodiscard]] constexpr std::uint8_t mask_byte(std::uint8_t value, std::size_t index) {
  return static_cast<std::uint8_t>(value ^ kHiddenStringKey ^ static_cast<std::uint8_t>(index * 7U + 1U));
}

/// A string literal stored XOR-masked at compile time, so its plaintext never appears in the binary.
///
/// @tparam N The size of the string literal including its terminating NUL.
template <std::size_t N>
class HiddenString {
 public:
  /// Builds a hidden string from a string literal, masking every byte at compile time.
  ///
  /// @param text The string literal, such as "/Applications/Cydia.app".
  consteval explicit HiddenString(const char (&text)[N]) {
    for (std::size_t index = 0; index < N; ++index) {
      masked_[index] = mask_byte(static_cast<std::uint8_t>(text[index]), index);
    }
  }

  /// Reveals the plaintext into a freshly allocated `std::string`.
  ///
  /// The returned string is a real, independent buffer: it is what a probe passes to a system call and reports. It
  /// lives only as long as the caller keeps it, so the plaintext is not resident in the image, only briefly on the
  /// heap while a probe runs.
  ///
  /// @return The plaintext, without the terminating NUL.
  [[nodiscard]] std::string reveal() const {
    std::string plaintext;
    plaintext.reserve(N - 1);
    for (std::size_t index = 0; index < N - 1; ++index) {
      plaintext.push_back(static_cast<char>(mask_byte(masked_[index], index)));
    }
    return plaintext;
  }

 private:
  /// The masked bytes, including the masked terminating NUL. Never holds plaintext.
  std::array<std::uint8_t, N> masked_{};
};

/// Reveals every hidden string of a parameter pack into a vector of `std::string`, in order.
///
/// Each HiddenString of a different length is a distinct type, so a plain array can't hold them; a pack keeps them
/// together and this reveals them all at once, right before a probe iterates the results.
///
/// @tparam Sizes The sizes of the hidden strings, deduced from the arguments.
/// @param hidden The hidden strings to reveal.
/// @return The plaintext strings, in the order given.
template <std::size_t... Sizes>
[[nodiscard]] std::vector<std::string> reveal_all(const HiddenString<Sizes>&... hidden) {
  return {hidden.reveal()...};
}

}  // namespace rasp::ios::util
