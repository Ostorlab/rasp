/// load_plugin: dlopen, dlsym of rasp_plugin_init, and the call to it.

#include "rasp/plugins/loader.h"

#include <dlfcn.h>
#include <string>

#include "rasp/plugin.h"

namespace rasp::plugins {

namespace {

/// The type of rasp_plugin_init.
using InitFunction = const rasp_plugin* (*)(const rasp_host* host);

/// The name of the one symbol a plugin exports.
constexpr const char* kInitSymbol = "rasp_plugin_init";

}  // namespace

const rasp_plugin* load_plugin(const std::string& path, const rasp_host& host) {
  void* const library = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (library == nullptr) {
    return nullptr;
  }
  void* const symbol = dlsym(library, kInitSymbol);
  if (symbol == nullptr) {
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): dlsym returns a function's address as a void*.
  const auto init = reinterpret_cast<InitFunction>(symbol);
  return init(&host);
}

}  // namespace rasp::plugins
