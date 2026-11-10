/// Tests for the mailbox.

#include "mailbox.h"

#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

namespace rasp::plugins::dns_reporting {
namespace {

TEST(DnsMailbox, putAndTake_whenOneBatch_returnsThatBatch) {
  Mailbox mailbox;
  mailbox.put({"a.rsp.test", "b.rsp.test"});

  const std::vector<std::string> taken = mailbox.take();

  ASSERT_EQ(taken.size(), 2U);
  EXPECT_EQ(taken[0], "a.rsp.test");
  EXPECT_EQ(taken[1], "b.rsp.test");
}

TEST(DnsMailbox, put_whenTwoBatchesBeforeTake_dropsTheFirst) {
  Mailbox mailbox;
  mailbox.put({"first.rsp.test"});
  mailbox.put({"second.rsp.test"});

  const std::vector<std::string> taken = mailbox.take();

  ASSERT_EQ(taken.size(), 1U);
  EXPECT_EQ(taken[0], "second.rsp.test");
}

TEST(DnsMailbox, take_whenEmpty_blocksUntilPut) {
  Mailbox mailbox;
  std::vector<std::string> taken;

  std::thread taker([&mailbox, &taken] { taken = mailbox.take(); });
  mailbox.put({"async.rsp.test"});
  taker.join();

  ASSERT_EQ(taken.size(), 1U);
  EXPECT_EQ(taken[0], "async.rsp.test");
}

}  // namespace
}  // namespace rasp::plugins::dns_reporting
