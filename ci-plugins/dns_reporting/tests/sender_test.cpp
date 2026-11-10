/// Tests for the sender, with a fake resolve.

#include "sender.h"

#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <vector>

namespace rasp::plugins::dns_reporting {
namespace {

constexpr std::chrono::seconds kWait{10};

struct Resolves {
  std::mutex mutex;
  std::condition_variable changed;
  std::vector<std::string> names;
  bool accept = true;
};

[[nodiscard]] Resolves& resolves() {
  static Resolves value;
  return value;
}

void reset_resolves() {
  Resolves& seen = resolves();
  const std::scoped_lock lock(seen.mutex);
  seen.names.clear();
  seen.accept = true;
}

bool fake_resolve(const std::string& name) noexcept {
  Resolves& seen = resolves();
  const std::scoped_lock lock(seen.mutex);
  seen.names.push_back(name);
  seen.changed.notify_all();
  return seen.accept;
}

TEST(DnsSender, deliver_whenAllResolve_resolvesEveryName) {
  reset_resolves();
  const Sender sender{.resolve = fake_resolve, .mailbox = {}};

  EXPECT_TRUE(deliver(sender, {"a.rsp.test", "b.rsp.test"}));

  const std::scoped_lock lock(resolves().mutex);
  ASSERT_EQ(resolves().names.size(), 2U);
  EXPECT_EQ(resolves().names[0], "a.rsp.test");
  EXPECT_EQ(resolves().names[1], "b.rsp.test");
}

TEST(DnsSender, deliver_whenFirstFails_stopsAndReturnsFalse) {
  reset_resolves();
  {
    const std::scoped_lock lock(resolves().mutex);
    resolves().accept = false;
  }
  const Sender sender{.resolve = fake_resolve, .mailbox = {}};

  EXPECT_FALSE(deliver(sender, {"a.rsp.test", "b.rsp.test"}));

  const std::scoped_lock lock(resolves().mutex);
  EXPECT_EQ(resolves().names.size(), 1U);
}

TEST(DnsSender, deliver_whenEmpty_returnsTrue) {
  reset_resolves();
  const Sender sender{.resolve = fake_resolve, .mailbox = {}};

  EXPECT_TRUE(deliver(sender, {}));

  const std::scoped_lock lock(resolves().mutex);
  EXPECT_TRUE(resolves().names.empty());
}

TEST(DnsSender, startSender_whenBatchArrives_resolvesIt) {
  reset_resolves();
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  auto* const sender = new Sender{.resolve = fake_resolve, .mailbox = {}};
  ASSERT_TRUE(start_sender(*sender));

  sender->mailbox.put({"thread.rsp.test"});

  Resolves& seen = resolves();
  std::unique_lock lock(seen.mutex);
  ASSERT_TRUE(seen.changed.wait_for(lock, kWait, [&seen] { return seen.names.size() == 1; }));
  EXPECT_EQ(seen.names[0], "thread.rsp.test");
}

}  // namespace
}  // namespace rasp::plugins::dns_reporting
