/// read_embedded_config: reads the config the packer writes into the runtime's binary.

#include "rasp/embedded_config.h"

#include <array>
#include <string>

#include "rasp/config.h"
#include "rasp/parse_config.h"

namespace rasp {

namespace {

/// The space the packer writes the config into, in its own section of the runtime's binary. It starts as `{}`, a config
/// with no field, so the section holds bytes in the file for the packer to overwrite. It is volatile, so every read
/// takes the bytes in the binary, which the packer changed, and never the initial ones the compiler knows.
#ifdef __APPLE__
[[gnu::section("__DATA,__rasp_config"), gnu::used]]
#else
[[gnu::section(".rasp_config"), gnu::used]]
#endif
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the packer writes it, in the binary's file.
std::array<volatile char, kEmbeddedConfigSize> embedded_config{'{', '}'};

}  // namespace

Config read_embedded_config() {
  std::string json;
  for (const volatile char& character : embedded_config) {
    if (character == '\0') {
      break;
    }
    json.push_back(character);
  }
  return parse_config(json);
}

}  // namespace rasp
