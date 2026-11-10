/// Tests for the sender, with a fake post: deliver wraps a run in a request and posts it once, a run that is not
/// delivered is left in the context, and the sender's thread posts the newest run.

#include "sender.h"

#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "config.h"
#include "json.h"
#include "rasp/context.h"
#include "rasp/observation.h"
#include "reporting/undelivered_run.h"

namespace rasp::plugins::reporting {
namespace {

/// How long a test waits for the sender's thread.
constexpr std::chrono::seconds kWait{10};

/// What the fake post saw, shared with the sender's thread.
struct Posts {
  /// Guards every other field.
  std::mutex mutex;
  /// Signalled when a post starts and when `hold` changes.
  std::condition_variable changed;
  /// The body of every post, in order.
  std::vector<std::string> bodies;
  /// The endpoint of every post, in order.
  std::vector<std::string> endpoints;
  /// What the fake post answers.
  bool accept = true;
  /// While `true`, a post waits before it answers.
  bool hold = false;
};

/// The posts the fake saw, shared by every test.
///
/// @return The posts.
[[nodiscard]] Posts& posts() {
  static Posts value;
  return value;
}

/// Forgets every post and resets the fake's answers.
void reset_posts() {
  Posts& seen = posts();
  const std::scoped_lock lock(seen.mutex);
  seen.bodies.clear();
  seen.endpoints.clear();
  seen.accept = true;
  seen.hold = false;
}

/// The fake post: records the post, waits while `hold` is set, and answers `accept`.
///
/// @param config The plugin's config.
/// @param body The request.
/// @return `accept`.
bool fake_post(const Config& config, std::string_view body) noexcept {
  Posts& seen = posts();
  std::unique_lock lock(seen.mutex);
  seen.bodies.emplace_back(body);
  seen.endpoints.push_back(config.endpoint);
  seen.changed.notify_all();
  seen.changed.wait(lock, [&seen] { return !seen.hold; });
  return seen.accept;
}

/// A sender that posts with the fake.
///
/// @param sender The sender to fill.
/// @param context The context the plugins share, where the sender leaves each run it does not deliver.
void configure(Sender& sender, Context& context) {
  sender.config = {.endpoint = "https://reports.example.com/rasp", .build_id = "build-7"};
  sender.post = fake_post;
  sender.context = &context;
}

/// A run of one observation.
///
/// @param signal The signal of the observation.
/// @return One observation of `signal`, true, read through test.
[[nodiscard]] std::vector<Observation> run_of(std::string_view signal) { return {observed(signal, "test", true)}; }

/// The context of the sender whose thread a test starts.
///
/// @return The context, which lives as long as the test process, as that thread does.
[[nodiscard]] Context& thread_context() {
  static Context value;
  return value;
}

TEST(Sender, deliver_whenPostAccepts_postsOneRequestToTheEndpointAndLeavesNothingInTheContext) {
  reset_posts();
  Context context;
  Sender sender;
  configure(sender, context);

  deliver(sender, run_of("test.ping"));

  EXPECT_EQ(context.get(kUndeliveredRun), std::nullopt);
  Posts& seen = posts();
  const std::scoped_lock lock(seen.mutex);
  ASSERT_EQ(seen.bodies.size(), 1U);
  EXPECT_EQ(seen.endpoints.front(), "https://reports.example.com/rasp");
  EXPECT_EQ(seen.bodies.front(),
            serialise_request(sender.config,
                              R"([{"signal":"test.ping","source":"test","status":"OK","value":{"bool":true}}])",
                              kMaxRequestSize));
}

TEST(Sender, deliver_whenPostFails_leavesTheRunInTheContextAfterOneAttempt) {
  reset_posts();
  {
    const std::scoped_lock lock(posts().mutex);
    posts().accept = false;
  }
  Context context;
  Sender sender;
  configure(sender, context);

  deliver(sender, run_of("test.ping"));

  EXPECT_EQ(context.get(kUndeliveredRun), run_of("test.ping"));
  const std::scoped_lock lock(posts().mutex);
  EXPECT_EQ(posts().bodies.size(), 1U);
}

TEST(Sender, deliver_whenTheRequestWouldBeTooLarge_leavesTheRunInTheContextWithoutPosting) {
  reset_posts();
  Context context;
  Sender sender;
  configure(sender, context);
  const std::vector<Observation> run{observed("test.large", "test", std::string(kMaxRequestSize, 'a'))};

  deliver(sender, run);

  EXPECT_EQ(context.get(kUndeliveredRun), run);
  const std::scoped_lock lock(posts().mutex);
  EXPECT_TRUE(posts().bodies.empty());
}

TEST(Sender, startSender_whenRunsArriveDuringAPost_postsOnlyTheNewestNext) {
  reset_posts();
  Posts& seen = posts();
  {
    const std::scoped_lock lock(seen.mutex);
    seen.hold = true;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): the sender's thread uses it until the process exits.
  auto* const sender = new Sender();
  configure(*sender, thread_context());
  ASSERT_TRUE(start_sender(*sender));

  sender->mailbox.put(run_of("test.first"));
  {
    std::unique_lock lock(seen.mutex);
    ASSERT_TRUE(seen.changed.wait_for(lock, kWait, [&seen] { return seen.bodies.size() == 1; }));
  }
  sender->mailbox.put(run_of("test.second"));
  sender->mailbox.put(run_of("test.third"));
  {
    const std::scoped_lock lock(seen.mutex);
    seen.hold = false;
  }
  seen.changed.notify_all();

  std::unique_lock lock(seen.mutex);
  ASSERT_TRUE(seen.changed.wait_for(lock, kWait, [&seen] { return seen.bodies.size() == 2; }));
  EXPECT_TRUE(seen.bodies.front().contains(R"("signal":"test.first")"));
  EXPECT_TRUE(seen.bodies.back().contains(R"("signal":"test.third")"));
}

}  // namespace
}  // namespace rasp::plugins::reporting
