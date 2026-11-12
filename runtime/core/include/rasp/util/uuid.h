/// Secure UUID generation without persistent or installation state.
#pragma once
#include <string>
namespace rasp::util {
/// Generates a random v4 UUID with the existing arc4random_buf source.
/// @return Nonzero lowercase RFC UUID text; unrelated to installation identity.
[[nodiscard]] std::string new_uuid();
}  // namespace rasp::util
