/// Tests for read_embedded_config, in a binary the packer has not written a config into.

#include "rasp/embedded_config.h"

#include <gtest/gtest.h>

namespace rasp {
namespace {

TEST(EmbeddedConfig, readEmbeddedConfig_whenThePackerWroteNoConfig_leavesTheBuildIdEmpty) {
  EXPECT_EQ(read_embedded_config().build_id, "");
}

}  // namespace
}  // namespace rasp
