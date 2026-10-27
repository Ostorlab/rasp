/// Tests for the registry the build generates for the runtime, from the plugins it was given.

#include "rasp/plugins/registry.h"

#include <cstddef>
#include <gtest/gtest.h>

namespace rasp::plugins {
namespace {

TEST(PluginRegistry, compiledIn_whenBuilt_holdsAsManyPluginsAsTheBuildWasGiven) {
  EXPECT_EQ(compiled_in().size(), std::size_t{RASP_EXPECTED_PLUGIN_COUNT});
}

}  // namespace
}  // namespace rasp::plugins
