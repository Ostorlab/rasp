/// Tests for kPlugin, the pin plugin: an init that needs no config, one check, no on_observations, and off an iPhone
/// both signals unsupported.

#include <gtest/gtest.h>
#include <vector>

#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"

namespace rasp::plugins::adr_pin {

extern const Plugin kPlugin;

namespace {

TEST(AdrPin, kPlugin_whenDeclared_hasAnInitOneCheckAndNoObservationHandler) {
  EXPECT_NE(kPlugin.init, nullptr);
  EXPECT_EQ(kPlugin.checks.size(), 1U);
  EXPECT_EQ(kPlugin.on_observations, nullptr);
}

TEST(AdrPin, init_whenConfigIsEmpty_returns) {
  const Config config;
  Context context;
  kPlugin.init(config, context);
}

TEST(AdrPin, check_whenOffAnIphone_reportsBothSignalsAsUnsupported) {
  const Check probe = kPlugin.checks[0];
  Context context;
  const std::vector<Observation> observations = probe(context);

  EXPECT_EQ(observations, (std::vector<Observation>{unsupported("mitm.adr_pin", "network_framework"),
                                                    unsupported("mitm.adr_trusted", "sec_trust")}));
}

}  // namespace
}  // namespace rasp::plugins::adr_pin
