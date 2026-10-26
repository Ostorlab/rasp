/// Reading Android system properties through the platform property store.

#include "util/system_property.h"

#include <optional>
#include <string>
#include <string_view>

#ifdef __ANDROID__
#include <cstdint>
#include <sys/system_properties.h>
#endif

namespace rasp::android::util {

#ifdef __ANDROID__

std::optional<std::string> read_system_property(std::string_view name) {
  const std::string key(name);
  const prop_info* const info = __system_property_find(key.c_str());
  if (info == nullptr) {
    return std::nullopt;
  }
  std::string value;
  __system_property_read_callback(
      info,
      [](void* cookie, const char* /*name*/, const char* text, std::uint32_t /*serial*/) {
        if (text != nullptr) {
          *static_cast<std::string*>(cookie) = text;
        }
      },
      &value);
  return value;
}

#else

std::optional<std::string> read_system_property([[maybe_unused]] std::string_view name) { return std::nullopt; }

#endif

}  // namespace rasp::android::util
