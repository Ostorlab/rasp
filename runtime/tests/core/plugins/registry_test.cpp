/// Tests for the registry the build generates for the runtime, from the plugins it was given.

#include "rasp/plugins/registry.h"

#include <gtest/gtest.h>
#include <string>

#include "rasp/plugin.h"

namespace rasp::plugins {
namespace {

TEST(PluginRegistry, compiledIn_whenBuilt_holdsThePluginsTheBuildWasGivenInOrder) {
  std::string names;
  for (const Plugin* const plugin : compiled_in()) {
    if (!names.empty()) {
      names += ',';
    }
    names += plugin->name;
  }

  EXPECT_EQ(names, RASP_EXPECTED_PLUGINS);
}

}  // namespace
}  // namespace rasp::plugins
