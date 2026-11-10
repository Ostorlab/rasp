/// Tests for kPlugin, the reporting plugin, through its init and its on_observations. The test defines the transport's
/// `post`, so the plugin's sender posts to it, and the test reads what it received and what the plugin left in the
/// context.

#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "config.h"
#include "json.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "reporting/undelivered_run.h"
#include "transport.h"

namespace rasp::plugins::reporting {

/// The reporting plugin, which the plugin's sources define.
extern const Plugin kPlugin;

namespace {

/// How long a test waits for the plugin's sender.
constexpr std::chrono::seconds kWait{10};
/// How long a test sleeps between two reads of the context while it waits for the plugin's sender.
constexpr std::chrono::milliseconds kPollInterval{10};

/// What the transport received, shared with the plugin's sender thread.
struct Received {
  /// Guards every other field.
  std::mutex mutex;
  /// Signalled after each post.
  std::condition_variable posted;
  /// The config of every post, in order.
  std::vector<Config> configs;
  /// The body of every post, in order.
  std::vector<std::string> bodies;
  /// What the transport answers.
  bool accept = true;
};

/// What the transport received in this process.
///
/// @return What it received.
[[nodiscard]] Received& received() {
  static Received value;
  return value;
}

/// Forgets every post, and sets what the transport answers.
///
/// @param accept What the transport answers from now on.
void reset_received(bool accept) {
  Received& seen = received();
  const std::scoped_lock lock(seen.mutex);
  seen.configs.clear();
  seen.bodies.clear();
  seen.accept = accept;
}

/// A new context the plugins share, for one test. It is never destroyed, because the plugin's sender keeps it until
/// the process exits.
///
/// @return The context.
[[nodiscard]] Context& new_context() {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): the plugin's sender uses it until the process exits.
  return *new Context();
}

/// Waits until the context holds the run the plugin did not deliver, for at most kWait.
///
/// @param context The context the plugins share.
/// @return All the observations of the run. Nothing when kWait passed first.
[[nodiscard]] std::optional<std::vector<Observation>> wait_for_undelivered_run(const Context& context) {
  const auto deadline = std::chrono::steady_clock::now() + kWait;
  std::optional<std::vector<Observation>> run = context.get(kUndeliveredRun);
  while (!run.has_value() && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(kPollInterval);
    run = context.get(kUndeliveredRun);
  }
  return run;
}

}  // namespace

/// The transport of the tests: it records each post and answers `accept`.
///
/// @param config The plugin's config.
/// @param body The request.
/// @return `accept`.
bool post(const Config& config, std::string_view body) noexcept {
  Received& seen = received();
  const std::scoped_lock lock(seen.mutex);
  seen.configs.push_back(config);
  seen.bodies.emplace_back(body);
  seen.posted.notify_all();
  return seen.accept;
}

namespace {

TEST(ReportingPlugin, kPlugin_hasAnInitNoCheckAndAnOnObservations) {
  EXPECT_NE(kPlugin.init, nullptr);
  EXPECT_TRUE(kPlugin.checks.empty());
  EXPECT_NE(kPlugin.on_observations, nullptr);
}

TEST(ReportingPlugin, onObservations_whenInitialisedThenGivenARun_postsItsObservationsToTheCompiledInEndpoint) {
  reset_received(true);
  Context& context = new_context();
  kPlugin.init({.build_id = "build-7"}, context);
  {
    const std::vector<Observation> run{observed("jb.fork_ok", "fork", false), failed("dbg.tracer_pid", "proc")};
    kPlugin.on_observations(run, context);
  }

  Received& seen = received();
  std::unique_lock lock(seen.mutex);
  ASSERT_TRUE(seen.posted.wait_for(lock, kWait, [&seen] { return !seen.bodies.empty(); }));
  ASSERT_EQ(seen.bodies.size(), 1U);
  EXPECT_EQ(seen.configs.front().endpoint, RASP_REPORTING_ENDPOINT);
  const std::string_view body = seen.bodies.front();
  EXPECT_EQ(body, R"({"query":")" + std::string(kMutation) +
                      R"(","variables":{"batch":{"installId":"00000000-0000-0000-0000-000000000000",)"
                      R"("sessionId":"00000000-0000-0000-0000-000000000000","buildId":"build-7","observations":[)"
                      R"({"signal":"jb.fork_ok","source":"fork","status":"OK","value":{"bool":false}},)"
                      R"({"signal":"dbg.tracer_pid","source":"proc","status":"ERROR","value":null}]}}})");
}

TEST(ReportingPlugin, init_whenGivenAnInstallId_givesItToTheSender) {
  reset_received(true);
  Context& context = new_context();
  kPlugin.init({.build_id = "build-7", .install_id = "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b"}, context);

  kPlugin.on_observations(std::vector<Observation>{observed("jb.fork_ok", "fork", false)}, context);

  Received& seen = received();
  std::unique_lock lock(seen.mutex);
  ASSERT_TRUE(seen.posted.wait_for(lock, kWait, [&seen] { return !seen.configs.empty(); }));
  EXPECT_EQ(seen.configs.front().install_id, "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b");
}

TEST(ReportingPlugin, onObservations_whenThePostFails_leavesTheRunInTheContext) {
  reset_received(false);
  Context& context = new_context();
  const std::vector<Observation> run{observed("jb.fork_ok", "fork", false), failed("dbg.tracer_pid", "proc")};
  kPlugin.init({.build_id = "build-7"}, context);

  kPlugin.on_observations(run, context);

  EXPECT_EQ(wait_for_undelivered_run(context), run);
}

}  // namespace
}  // namespace rasp::plugins::reporting
