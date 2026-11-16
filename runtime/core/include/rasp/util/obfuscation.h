/// anchor_literals, which keeps string literals where the release string obfuscator can encrypt them.

#pragma once

#include <span>
#include <string_view>

namespace rasp::util {

/// Makes the release build's string obfuscation encrypt `literals`, which it misses when they are only used through
/// `constexpr std::string_view` constants.
///
/// @param literals The string literals to encrypt.
[[gnu::always_inline]] inline void anchor_literals(std::span<const std::string_view> literals) {
  for (const std::string_view literal : literals) {
    const char* volatile address = literal.data();
    static_cast<void>(address);
  }
}

}  // namespace rasp::util
