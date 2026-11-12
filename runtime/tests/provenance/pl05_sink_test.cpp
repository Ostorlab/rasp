/// Actual normal dispatch and controlled native boundaries feed frozen PL05 serializers, storage, retry and DNS.
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

#include "builtin.h"
#include "checks/module_provenance.h"
#include "config.h"
#include "cycle_delivery.h"
#include "cycle_dns.h"
#include "cycle_payload.h"
#include "dns_frame.h"
#include "json.h"
#include "outbox.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/posix/private_storage.h"
#include "rasp/posix/provenance.h"
#include "rasp/private_storage.h"
#include "reporting/transport_result.h"
#include "reporting/undelivered_run.h"
#include "security_profile.h"
#include "sender.h"
#include "support/files.h"
#include "transport.h"
#ifdef RASP_CAPABILITY_ANDROID
#include "checks/loader_provenance.h"
#else
#include <utility>
#endif

namespace {
namespace reporting = rasp::plugins::reporting;
namespace dns = rasp::plugins::dns_reporting;
/// No transport opens a socket; the actual sender invokes this typed public I/O boundary.
struct State {
  std::string root;
  std::string request;
  std::size_t posts = 0;
  std::int64_t now = 0;
  reporting::TransportResult result = reporting::TransportResult::kIoFailed;
};
/// Fixture state is process-local; production owns no new global object.
State& state() {
  static State value;
  return value;
}
/// Captures the original publication request and preserves typed refusal semantics.
reporting::TransportResult capture(const reporting::Config& /*config*/, std::string_view body,
                                   reporting::Cancellation /*cancellation*/) noexcept {
  state().request = body;
  ++state().posts;
  return state().result;
}
/// The real provider owns permissions and stable install identity under an isolated directory.
std::expected<rasp::PrivateStorage, rasp::StorageError> acquire() {
  return rasp::posix::acquire_private_storage_at(state().root);
}
/// Fake retry time does not change PL05's real active system security profile.
std::int64_t clock() { return state().now; }
/// Actual runtime builtin dispatcher, unchanged by controlled-source testing.
std::vector<rasp::Observation> normal(const rasp::Config& config, const void* /*argument*/) {
#ifdef RASP_CAPABILITY_ANDROID
  return rasp::android::run_checks(config);
#else
  return rasp::ios::run_checks(config, "");
#endif
}
/// The fixed parser clock avoids scheduler-dependent source outcomes.
std::int64_t source_clock() { return 0; }
#ifdef RASP_CAPABILITY_ANDROID
/// Raw native I/O fixture, never a preclassified observation vector.
struct Maps {
  std::string text = "1000-2000 r-xp 0 00:01 1 /data/app/rt19-private-sentinel/lib/plugin.so\n";
  std::size_t offset = 0;
  rasp::provenance::Error failure = rasp::provenance::Error::kNone;
};
/// The monitor argument retains a mutable native I/O context without casting away const.
struct Invocation {
  Maps* maps;
};
/// Opening resets a complete independent map snapshot.
int open_maps(void* context) {
  auto& maps = *static_cast<Maps*>(context);
  maps.offset = 0;
  return maps.failure == rasp::provenance::Error::kDenied ? -EACCES : 7;
}
/// Returns exact fixture bytes through the production read loop.
rasp::android::checks::MapRead read_maps(void* context, int /*descriptor*/, std::span<char> into) {
  auto& maps = *static_cast<Maps*>(context);
  const auto size = std::min(into.size(), maps.text.size() - maps.offset);
  std::copy_n(maps.text.begin() + static_cast<std::ptrdiff_t>(maps.offset), size, into.begin());
  maps.offset += size;
  return {.size = static_cast<std::int64_t>(size)};
}
/// Every simulated descriptor is owned for one actual collector read.
int close_maps(void* /*context*/, int /*descriptor*/) { return 0; }
/// The intended native interval validator still processes the copied header reduction.
rasp::provenance::Result<std::vector<rasp::android::checks::ExecutableImage>> images(
    void* context, rasp::provenance::Budget& /*budget*/) {
  const auto& maps = *static_cast<Maps*>(context);
  if (maps.failure != rasp::provenance::Error::kNone) {
    return std::unexpected(maps.failure);
  }
  return std::vector<rasp::android::checks::ExecutableImage>{
      {
          .name = "/data/app/rt19-private-sentinel/lib/plugin.so",
          .intervals = {{.start = 0x1000, .end = 0x2000, .flags = 5}},
      },
  };
}
/// Replaces only native I/O for the actual bounded parser/reducer after the historical builtin prefix.
std::vector<rasp::Observation> controlled(const rasp::Config& config, const void* argument) {
  auto rows = normal(config, nullptr);
  auto* maps = static_cast<const Invocation*>(argument)->maps;
  rows.resize(rows.size() - 6);
  const auto modules = rasp::android::checks::collect_module_provenance(
      {
          .apk_paths = {},
          .native_directory = "/data/app/rt19-private-sentinel/lib",
          .bundle_directory = {},
          .available = true,
      },
      {
          .maps = {.context = maps, .open = open_maps, .read = read_maps, .close = close_maps},
          .context = maps,
          .images = images,
      },
      source_clock);
  rows.insert(rows.end(), modules.begin(), modules.end());
  const auto topology = rasp::android::checks::read_loader_provenance(nullptr, nullptr);
  rows.insert(rows.end(), topology.begin(), topology.end());
  return rows;
}
#else
/// Copied dyld boundary input, using the same minimal executable segment as the Stage A parser fixtures.
struct DyldInput {
  rasp::provenance::Error failure = rasp::provenance::Error::kNone;
  std::uint32_t count = 1;
};
/// The public count boundary exposes only bounded fixture image counts.
rasp::provenance::Result<std::uint32_t> image_count(void* context, rasp::provenance::Budget& /*budget*/) {
  return static_cast<DyldInput*>(context)->count;
}
/// Supplies raw Mach-O bytes; the real production parser/bracketing/reducer handles every field.
rasp::provenance::Result<rasp::ios::checks::ProvenanceImage> copied_image(void* context, std::uint32_t index,
                                                                          rasp::provenance::Budget& /*budget*/) {
  const auto failure = static_cast<DyldInput*>(context)->failure;
  if (failure != rasp::provenance::Error::kNone) {
    return std::unexpected(failure);
  }
  std::vector<std::uint8_t> bytes(104);
  constexpr std::array<std::pair<std::size_t, std::uint32_t>, 9> kFields{
      {
          {0, 0xfeedfacf},
          {16, 1},
          {20, 72},
          {32, 0x19},
          {36, 72},
          {56, 0x1000},
          {64, 0x1000},
          {80, 0x800},
          {92, 5},
      },
  };
  for (const auto& [offset, value] : kFields) {
    for (std::size_t byte = 0; byte < 4; ++byte) {
      bytes[offset + byte] = static_cast<std::uint8_t>(value >> (byte * 8U));
    }
  }
  return rasp::ios::checks::ProvenanceImage{
      .name = "/private/app/rt19-private-sentinel.app/Frameworks/Private.framework/Private",
      .header_address = 0x1000 + (static_cast<std::uintptr_t>(index) * 0x1000),
      .slide = 0,
      .bytes = std::move(bytes),
  };
}
/// Only copied dyld I/O changes; normal old hooks and the actual collector are retained.
std::vector<rasp::Observation> controlled(const rasp::Config& config, const void* argument) {
  auto rows = normal(config, nullptr);
  auto input = *static_cast<const DyldInput*>(argument);
  rows.resize(rows.size() - 2);
  const auto modules = rasp::ios::checks::collect_module_provenance(
      {
          .apk_paths = {},
          .native_directory = {},
          .bundle_directory = "/private/app/rt19-private-sentinel.app",
          .available = true,
      },
      {.context = &input, .count = image_count, .image = copied_image}, source_clock);
  rows.insert(rows.end(), modules.begin(), modules.end());
  return rows;
}
#endif
/// Checks only new pairs; historical hook paths are intentionally not filtered or claimed path-free.
void reduced(std::span<const rasp::Observation> rows) {
  std::size_t count = 0;
  for (const auto& row : rows) {
    if (!row.signal.starts_with("hook.exec_modules") && !row.signal.starts_with("hook.loader_chain")) {
      continue;
    }
    ++count;
    EXPECT_EQ(rasp::describe(row).find("rt19-private-sentinel"), std::string::npos);
    EXPECT_EQ(rasp::describe(row).find("0x1000"), std::string::npos);
    if (row.status != rasp::Status::kOk) {
      EXPECT_TRUE(std::holds_alternative<std::monostate>(row.value));
    }
  }
#ifdef RASP_CAPABILITY_ANDROID
  EXPECT_EQ(count, 6U);
#else
  EXPECT_EQ(count, 2U);
#endif
}
/// Writes the real native producer bytes for the separately sequenced backend adoption worker.
struct OutputLocation {
  std::string_view lane;
  std::string_view filename;
};
/// Writes one actual producer artifact to its explicitly named local evidence destination.
void output(const OutputLocation& location, std::string_view bytes) {
  std::error_code error;
#ifdef RASP_CAPABILITY_ANDROID
  const auto* const platform = "android";
#else
  const auto* const platform = "ios";
#endif
  const auto directory = std::filesystem::path(RASP_PROVENANCE_EMITTED) / platform / location.lane;
  std::filesystem::create_directories(directory, error);
  ASSERT_FALSE(error);
  std::ofstream file(directory / location.filename, std::ios::binary);
  file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  file.close();
  ASSERT_TRUE(file);
}
/// Real completed cycle with actual generated catalogue and selected hooks coverage.
std::shared_ptr<const rasp::CycleSnapshot> snapshot(std::vector<rasp::Observation> (*dispatch)(const rasp::Config&,
                                                                                               const void*) = normal,
                                                    const void* argument = nullptr) {
  const rasp::Config selection{.build_id = std::string(64, 'b'), .checks = std::vector<std::string>{"hooks"}};
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
#ifdef RASP_CAPABILITY_ANDROID
  const auto catalogue = rasp::cycle_catalogue("android");
#else
  const auto catalogue = rasp::cycle_catalogue("ios");
#endif
  return monitor.run(selection, catalogue, {}, context, dispatch, argument);
}
/// Drives actual legacy and owning publication, persistence, restore and DNS without starting plugin threads.
void roundtrip(std::string_view lane, const std::shared_ptr<const rasp::CycleSnapshot>& run) {
  state() = {};
  const rasp::test_support::TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  state().root = directory.path();
  ASSERT_NE(run, nullptr);
  EXPECT_TRUE(run->metadata.complete);
  reduced(run->observations);
  const reporting::Config config{
      .endpoint = "https://collector.example/apis/graphql",
      .build_id = std::string(64, 'b'),
      .security_profile = std::string(reporting::compiled_security_profile()),
  };
  dns::register_cycle_dns();
  rasp::plugins::Context context;
  const reporting::Sender legacy{.config = config, .post = capture, .context = &context, .mailbox = {}};
  reporting::deliver(legacy, run->observations);
  ASSERT_EQ(state().posts, 1U);
  EXPECT_LE(state().request.size(), reporting::kMaxRequestSize);
  EXPECT_TRUE(context.get(reporting::kAuthorizedUndeliveredRun).has_value());
  output({.lane = lane, .filename = "legacy-request.json"}, state().request);
  state().result = reporting::TransportResult::kTrustVerificationFailed;
  rasp::plugins::Context refused;
  const reporting::Sender suppressed{.config = config, .post = capture, .context = &refused, .mailbox = {}};
  reporting::deliver(suppressed, run->observations);
  EXPECT_FALSE(refused.get(reporting::kAuthorizedUndeliveredRun).has_value());
  const auto suppressed_run = refused.get(reporting::kSecuritySuppressedRun);
  ASSERT_TRUE(suppressed_run.has_value());
  reduced(*suppressed_run);
  state().result = reporting::TransportResult::kIoFailed;
  {
    reporting::CycleDelivery worker(config, capture, acquire, clock);
    ASSERT_TRUE(worker.admit(run));
    worker.step();
  }
  auto storage = acquire();
  ASSERT_TRUE(storage.has_value());
  reporting::Outbox box(storage->native_handle(), std::string(storage->install_id()));
  ASSERT_TRUE(box.initialize().has_value());
  const auto scan = box.scan();
  ASSERT_TRUE(scan.has_value());
  ASSERT_EQ(scan->records.size(), 1U);
  const auto& record = scan->records[0];
  EXPECT_LE(record.payload->canonical.size(), reporting::kMaxCanonicalBytes);
  EXPECT_LE(record.payload->request.size(), reporting::kMaxCycleRequestBytes);
  output({.lane = lane, .filename = "canonical.json"}, record.payload->canonical);
  output({.lane = lane, .filename = "request.json"}, record.payload->request);
  output({.lane = lane, .filename = "dns.json"}, record.payload->dns_json);
  EXPECT_EQ(record.payload->serialization_dropped, 0U);
  const auto restored = reporting::restore_cycle(record.payload->canonical);
  ASSERT_TRUE(restored.has_value());
  EXPECT_EQ(restored->canonical, record.payload->canonical);
  const auto frame = dns::build_cycle_payload(*record.payload, {1, 2, 3, 4}, 1);
  ASSERT_FALSE(frame.empty());
  EXPECT_LE(frame.size(), dns::kMaxPayloadBytes);
  output({.lane = lane, .filename = "dns.bin"}, std::string(frame.begin(), frame.end()));
  const auto names = dns::build_cycle_report(*record.payload, record.authority, {1, 2, 3, 4}, 1);
  ASSERT_FALSE(names.empty());
  EXPECT_LE(names.size(), dns::kMaxChunks);
  std::string queries;
  for (const auto& name : names) {
    EXPECT_LE(name.size(), 253U);
    queries += name + "\n";
  }
  output({.lane = lane, .filename = "dns.names"}, queries);
  for (unsigned attempt = 0; attempt < 40; ++attempt) {
    ASSERT_TRUE(box.reserve(record.token).has_value());
  }
  /// A matched old native record has no TTL; active original system profile and exact authority are unchanged.
  state().now = 3153600000000000000;
  reporting::CycleDelivery restarted(config, capture, acquire, clock);
  const auto before = state().posts;
  restarted.step();
  EXPECT_EQ(state().posts, before);
  state().now += 299000000000;
  restarted.step();
  EXPECT_EQ(state().posts, before);
  state().now += 1000000000;
  restarted.step();
  ASSERT_EQ(state().posts, before + 1);
  EXPECT_EQ(state().request, record.payload->request);
  const auto retained = box.scan();
  ASSERT_TRUE(retained.has_value());
  ASSERT_EQ(retained->records.size(), 1U);
  EXPECT_EQ(retained->records[0].stage, 16U);
  EXPECT_EQ(retained->records[0].payload->canonical, record.payload->canonical);
}
TEST(NativeProvenanceSinks, normalProduction_whenSelected_preservesPairsAcrossLegacyOwningOutboxAndDNS) {
  roundtrip("normal", snapshot());
}
#ifdef RASP_CAPABILITY_ANDROID
TEST(NativeProvenanceSinks, controlledNativeBoundary_whenValidDeniedDeadlineOrSampled_keepsActualReducerAndStatus) {
  for (const auto failure :
       {rasp::provenance::Error::kNone, rasp::provenance::Error::kDenied, rasp::provenance::Error::kDeadline}) {
    Maps maps;
    maps.failure = failure;
    const Invocation invocation{.maps = &maps};
    const auto run = snapshot(controlled, &invocation);
    const auto row = std::ranges::find_if(run->observations, [](const auto& item) {
      return item.signal == "hook.exec_modules" && item.source == "dl_iterate_phdr_v1";
    });
    ASSERT_NE(row, run->observations.end());
    EXPECT_EQ(row->status, failure == rasp::provenance::Error::kNone       ? rasp::Status::kOk
                           : failure == rasp::provenance::Error::kDeadline ? rasp::Status::kTimeout
                                                                           : rasp::Status::kError);
    std::string_view lane = "controlled";
    if (failure == rasp::provenance::Error::kDenied) {
      lane = "denied";
    } else if (failure == rasp::provenance::Error::kDeadline) {
      lane = "timeout";
    }
    roundtrip(lane, run);
  }
  Maps maps;
  maps.text.clear();
  for (unsigned index = 0; index < 33; ++index) {
    maps.text += std::to_string(10000 + (index * 100)) + "-" + std::to_string(10050 + (index * 100)) +
                 " r-xp 0 00:01 1 /data/app/rt19-private-sentinel/plugin.so\n";
  }
  const Invocation invocation{.maps = &maps};
  roundtrip("sample33", snapshot(controlled, &invocation));
}
#else
TEST(NativeProvenanceSinks, copiedDyldBoundary_whenValidDeniedDeadlineOrSampled_preservesActualParserAndWire) {
  for (const auto& entry : std::array{
           std::pair{"controlled", rasp::provenance::Error::kNone},
           std::pair{"denied", rasp::provenance::Error::kDenied},
           std::pair{"timeout", rasp::provenance::Error::kDeadline},
           std::pair{"unknown", rasp::provenance::Error::kUnrecognized},
       }) {
    const DyldInput input{.failure = entry.second};
    const auto run = snapshot(controlled, &input);
    const auto row =
        std::ranges::find_if(run->observations, [](const auto& item) { return item.signal == "hook.exec_modules"; });
    ASSERT_NE(row, run->observations.end());
    EXPECT_EQ(row->status, rasp::provenance::status(entry.second));
    roundtrip(entry.first, run);
  }
  const DyldInput input{.count = 33};
  roundtrip("sample33", snapshot(controlled, &input));
}
#endif
}  // namespace

namespace {
/// Actual retained/serialization loss remains explicit; no pair filter or cap increase is introduced.
TEST(NativeProvenanceSinks, producerLoss_whenNativeOrSerializerDrops_keepsIncompleteEvidenceAndOriginalCaps) {
  const auto run = snapshot();
  ASSERT_NE(run, nullptr);
  auto copied = *run;
  const auto metadata =
      std::ranges::find_if(copied.observations, [](const auto& row) { return row.signal == "hook.exec_modules_meta"; });
  ASSERT_NE(metadata, copied.observations.end());
  metadata->value = std::string(1025, 'a');
  const auto prepared = reporting::prepare_cycle(copied, std::string(64, 'b'), "48bd44a5-c250-45d7-944e-4f110721dc90",
                                                 "615d890e-7ff1-499e-8f11-6dcfc58f7b0f");
  ASSERT_TRUE(prepared.has_value());
  EXPECT_EQ(prepared->serialization_dropped, 1U);
  EXPECT_NE(prepared->canonical.find("\"serialization_complete\":false"), std::string::npos);
  EXPECT_EQ(prepared->canonical.find(std::string(1025, 'a')), std::string::npos);
  EXPECT_TRUE(run->metadata.complete);
  /// Plugin retention operates in the real native monitor, after builtin coverage accounting.
  constexpr std::array<rasp::plugins::Check, 1> kChecks{
      [](rasp::plugins::Context&) {
        return std::vector<rasp::Observation>(300, rasp::observed("fixture.overflow", "test", std::string(512, 'b')));
      },
  };
  const rasp::plugins::Plugin overflow_plugin{.init = nullptr, .checks = kChecks};
  const std::array plugins{&overflow_plugin};
  const rasp::Config config{.build_id = std::string(64, 'b'), .checks = std::vector<std::string>{"hooks"}};
  rasp::plugins::Context context;
  rasp::CycleMonitor monitor;
#ifdef RASP_CAPABILITY_ANDROID
  const auto catalogue = rasp::cycle_catalogue("android");
#else
  const auto catalogue = rasp::cycle_catalogue("ios");
#endif
  const auto overflow = monitor.run(config, catalogue, plugins, context, normal);
  ASSERT_NE(overflow, nullptr);
  EXPECT_FALSE(overflow->metadata.complete);
  EXPECT_GT(overflow->metadata.dropped, 0U);
  EXPECT_LE(overflow->observations.size(), 256U);
  const auto oversized = reporting::prepare_cycle(
      *overflow, std::string(64, 'b'), "48bd44a5-c250-45d7-944e-4f110721dc90", "615d890e-7ff1-499e-8f11-6dcfc58f7b0f");
  ASSERT_TRUE(oversized.has_value());
  EXPECT_LE(oversized->canonical.size(), reporting::kMaxCanonicalBytes);
  EXPECT_LE(oversized->request.size(), reporting::kMaxCycleRequestBytes);
  EXPECT_TRUE(reporting::restore_cycle(oversized->canonical).has_value());
  EXPECT_TRUE(dns::build_cycle_payload(*oversized, {1, 2, 3, 4}, 1).empty());
  output({.lane = "pressure", .filename = "canonical.json"}, oversized->canonical);
  output({.lane = "pressure", .filename = "request.json"}, oversized->request);
}
}  // namespace
