#include "rasp/observation.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace rasp {
namespace {

TEST(Observation, describe_whenItHasAValue_showsTheValue) {
  const Observation observation{
      .signal = "jb.fs_paths",
      .source = "stat",
      .status = Status::kOk,
      .value = std::vector<std::string>{"/bin/sh", "/var/jb"},
  };

  EXPECT_EQ(describe(observation), "jb.fs_paths/stat ok [/bin/sh, /var/jb]");
}

TEST(Observation, describe_whenItHasNoValue_showsOnlyTheStatus) {
  const Observation observation{.signal = "jb.fork_ok", .source = "fork", .status = Status::kUnsupported, .value = {}};

  EXPECT_EQ(describe(observation), "jb.fork_ok/fork unsupported");
}

TEST(Observation, describe_whenTheValueIsABooleanOrALong_writesItAsText) {
  EXPECT_EQ(describe({.signal = "jb.fork_ok", .source = "fork", .status = Status::kOk, .value = true}),
            "jb.fork_ok/fork ok true");
  EXPECT_EQ(describe({.signal = "dbg.tracer_pid",
                      .source = "sysctl",
                      .status = Status::kOk,
                      .value = std::int64_t{1'099'511'627'776}}),
            "dbg.tracer_pid/sysctl ok 1099511627776");
}

}  // namespace
}  // namespace rasp
