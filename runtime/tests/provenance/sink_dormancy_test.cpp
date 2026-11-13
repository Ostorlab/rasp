/// Frozen actual legacy Sender, canonical serializer, durable worker/outbox and DNS encoder receive unchanged dispatch.
#include <chrono>
#include <cstdint>
#include <expected>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "builtin.h"
#include "collection_authority.h"
#include "config.h"
#include "cycle_delivery.h"
#include "cycle_dns.h"
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
namespace dns = rasp::plugins::dns_reporting;
/// Test-process state; real transports are replaced only at their public I/O boundary.
struct SinkState {
  std::string root;
  std::string request;
  std::uint64_t posts = 0;
  std::int64_t now = 0;
};
/// Accesses the bounded single-threaded fixture; no production worker thread is started.
SinkState& state() {
  static SinkState value;
  return value;
}
/// Copies actual serialized POST bytes without contacting a remote collector.
bool capture_post(const reporting::Config& /*config*/, std::string_view body) noexcept {
  state().request = body;
  ++state().posts;
  return false;
}
/// Acquires actual provider-owned storage under an isolated test directory.
std::expected<rasp::PrivateStorage, rasp::StorageError> storage() {
  return rasp::posix::acquire_private_storage_at(state().root);
}
/// Drives durable retry without wall-clock sleeps.
std::int64_t clock() { return state().now; }
/// Calls the inherited builtin graph; no collector object is linked into this executable.
std::vector<rasp::Observation> builtins(const rasp::Config& config, const void* /*argument*/) {
#ifdef RASP_CAPABILITY_ANDROID
  return rasp::android::run_checks(config);
#else
  return rasp::ios::run_checks(config, "");
#endif
}
/// Rejects accidental activation in actual output/serialized bytes, without filtering data.
void absent(std::string_view text) {
  EXPECT_EQ(text.find("hook.exec_modules"), std::string::npos);
  EXPECT_EQ(text.find("hook.loader_chain"), std::string::npos);
}
TEST(ProvenanceSinkDormancy, actualDispatch_whenReportingSinksSelected_containsNoNewPairs) {
  state() = {};
  const rasp::test_support::TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  state().root = directory.path();
  const rasp::Config selection{.build_id = std::string(64, 'b'), .checks = std::vector<std::string>{"hooks"}};
  const reporting::Config config{.endpoint = "https://collector.example/apis/graphql", .build_id = selection.build_id};
  rasp::plugins::Context context;
  const reporting::Sender sender{.config = config, .post = capture_post, .context = &context, .mailbox = {}};
  reporting::deliver(sender, builtins(selection, nullptr));
  ASSERT_EQ(state().posts, 1U);
  absent(state().request);
  rasp::CycleMonitor monitor;
#ifdef RASP_CAPABILITY_ANDROID
  const auto catalogue = rasp::cycle_catalogue("android");
#else
  const auto catalogue = rasp::cycle_catalogue("ios");
#endif
  const auto snapshot = monitor.run(selection, catalogue, {}, context, builtins);
  ASSERT_NE(snapshot, nullptr);
  ASSERT_TRUE(snapshot->metadata.complete);
  reporting::CycleDelivery worker(config, capture_post, storage, clock);
  ASSERT_TRUE(worker.admit(snapshot));
  worker.step();
  auto provider = storage();
  ASSERT_TRUE(provider.has_value());
  reporting::Outbox box(provider->native_handle(), std::string(provider->install_id()));
  ASSERT_TRUE(box.initialize().has_value());
  const auto scan = box.scan();
  ASSERT_TRUE(scan.has_value());
  ASSERT_EQ(scan->records.size(), 1U);
  const auto& record = scan->records[0];
  absent(record.payload->canonical);
  absent(record.payload->request);
  absent(record.payload->dns_json);
  state().now = 2000000000;
  worker.step();
  ASSERT_EQ(state().posts, 2U);
  absent(state().request);
  const auto binding = reporting::collection_authority(
      {.endpoint = config.endpoint, .policy = "default", .zone = "r.example", .dns_policy = "default"});
  ASSERT_TRUE(binding.has_value());
  const auto frame = dns::build_cycle_payload(*record.payload, {1, 2, 3, 4}, 1);
  ASSERT_FALSE(frame.empty());
  absent(std::string(frame.begin(), frame.end()));
  const auto names = dns::build_cycle_report(*record.payload, *binding, {1, 2, 3, 4}, 1);
  ASSERT_FALSE(names.empty());
  const auto restarted = box.scan();
  ASSERT_TRUE(restarted.has_value());
  ASSERT_EQ(restarted->records.size(), 1U);
  EXPECT_EQ(restarted->records[0].payload->canonical, record.payload->canonical);
  EXPECT_EQ(restarted->records[0].payload->batch_id, record.payload->batch_id);
}
}  // namespace

namespace rasp::plugins::dns_reporting {
/// This fixture never elects a DNS worker; any unexpected resolver call is a test failure.
bool resolve_until(const std::string& /*name*/, std::chrono::steady_clock::time_point /*deadline*/) noexcept {
  ADD_FAILURE() << "Unexpected DNS network operation";
  return false;
}
}  // namespace rasp::plugins::dns_reporting
