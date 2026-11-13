/// Explicit collector invocation proves inherited sinks serialize/spool observations without catalogue admission.
#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "checks/loader_provenance.h"
#include "checks/module_provenance.h"
#include "config.h"
#include "cycle_delivery.h"
#include "cycle_dns.h"
#include "cycle_payload.h"
#include "ios/src/checks/module_provenance.h"
#include "outbox.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/posix/private_storage.h"
#include "rasp/private_storage.h"
#include "sender.h"
#include "support/files.h"

namespace {
namespace reporting = rasp::plugins::reporting;
struct Exposure {
  std::string root;
  std::string request;
  unsigned posts = 0;
  std::int64_t now = 0;
};
Exposure& exposure() {
  static Exposure value;
  return value;
}
bool capture(const reporting::Config& /*config*/, std::string_view body) noexcept {
  exposure().request = body;
  ++exposure().posts;
  return false;
}
std::expected<rasp::PrivateStorage, rasp::StorageError> storage() {
  return rasp::posix::acquire_private_storage_at(exposure().root);
}
std::int64_t clock() { return exposure().now; }
std::vector<rasp::Observation> explicit_collectors(const rasp::Config& /*config*/, const void* /*argument*/) {
  auto rows = rasp::android::checks::collect_module_provenance({});
  const auto topology = rasp::android::checks::read_loader_provenance(nullptr, nullptr);
  rows.insert(rows.end(), topology.begin(), topology.end());
  const auto dyld = rasp::ios::checks::collect_module_provenance({});
  rows.insert(rows.end(), dyld.begin(), dyld.end());
  return rows;
}
void present(std::string_view bytes) {
  for (const auto* const name :
       {"hook.exec_modules", "hook.exec_modules_meta", "hook.loader_chain", "hook.loader_chain_meta"}) {
    EXPECT_NE(bytes.find(name), std::string::npos) << name;
  }
  EXPECT_EQ(bytes.find("/proc/"), std::string::npos);
  EXPECT_EQ(bytes.find("/usr/"), std::string::npos);
}
TEST(ProvenanceSinkExposure, explicitPairs_whenDelivered_areNotFilteredAndHaveNoFiniteLocalTTL) {
  exposure() = {};
  const rasp::test_support::TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  exposure().root = directory.path();
  const rasp::Config selected{.build_id = std::string(64, 'a'), .checks = std::vector<std::string>{"hooks"}};
  const reporting::Config config{.endpoint = "https://collector.example/apis/graphql", .build_id = selected.build_id};
  rasp::plugins::Context context;
  const reporting::Sender sender{.config = config, .post = capture, .context = &context, .mailbox = {}};
  reporting::deliver(sender, explicit_collectors(selected, nullptr));
  ASSERT_EQ(exposure().posts, 1U);
  present(exposure().request);
  rasp::CycleMonitor monitor;
  const auto snapshot = monitor.run(selected, rasp::cycle_catalogue("android"), {}, context, explicit_collectors);
  ASSERT_NE(snapshot, nullptr);
  EXPECT_FALSE(snapshot->metadata.complete);
  EXPECT_EQ(snapshot->metadata.extra, 8U);
  reporting::CycleDelivery worker(config, capture, storage, clock);
  ASSERT_TRUE(worker.admit(snapshot));
  worker.step();
  auto provider = storage();
  ASSERT_TRUE(provider.has_value());
  reporting::Outbox box(provider->native_handle(), std::string(provider->install_id()));
  ASSERT_TRUE(box.initialize().has_value());
  const auto scan = box.scan();
  ASSERT_TRUE(scan.has_value());
  ASSERT_EQ(scan->records.size(), 1U);
  const auto& original = *scan->records[0].payload;
  present(original.canonical);
  present(original.request);
  present(original.dns_json);
  const auto restored = reporting::restore_cycle(original.canonical);
  ASSERT_TRUE(restored.has_value());
  EXPECT_EQ(restored->canonical, original.canonical);
  EXPECT_EQ(restored->batch_id, original.batch_id);
  /// This is a limitation assertion, not a promised retention policy or erasure test.
  exposure().now = 3153600000000000000;
  worker.step();
  ASSERT_EQ(exposure().posts, 2U);
  present(exposure().request);
  EXPECT_EQ(exposure().request, original.request);
  const auto retained = box.scan();
  ASSERT_TRUE(retained.has_value());
  ASSERT_EQ(retained->records.size(), 1U);
  EXPECT_EQ(retained->records[0].payload->canonical, original.canonical);
}
}  // namespace
namespace rasp::plugins::dns_reporting {
bool resolve_until(const std::string& /*name*/, std::chrono::steady_clock::time_point /*deadline*/) noexcept {
  ADD_FAILURE() << "Unexpected network call";
  return false;
}
}  // namespace rasp::plugins::dns_reporting
