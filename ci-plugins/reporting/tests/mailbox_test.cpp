/// Tests for Mailbox: it keeps only the newest run, and take waits for a put.

#include "mailbox.h"

#include <gtest/gtest.h>
#include <string_view>
#include <thread>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins::reporting {
namespace {

/// A run of one observation.
///
/// @param signal The signal of the observation.
/// @return One observation of `signal`, true, read through test.
[[nodiscard]] std::vector<Observation> run_of(std::string_view signal) { return {observed(signal, "test", true)}; }

TEST(Mailbox, take_whenOneRunPut_returnsIt) {
  Mailbox mailbox;

  mailbox.put(run_of("test.first"));

  EXPECT_EQ(mailbox.take(), run_of("test.first"));
}

TEST(Mailbox, put_whenARunIsWaiting_keepsOnlyTheNewest) {
  Mailbox mailbox;

  mailbox.put(run_of("test.first"));
  mailbox.put(run_of("test.second"));
  mailbox.put(run_of("test.third"));

  EXPECT_EQ(mailbox.take(), run_of("test.third"));
}

TEST(Mailbox, take_whenNothingPutYet_waitsForThePut) {
  Mailbox mailbox;
  std::vector<Observation> taken;

  std::thread sender([&mailbox, &taken] { taken = mailbox.take(); });
  mailbox.put(run_of("test.late"));
  sender.join();

  EXPECT_EQ(taken, run_of("test.late"));
}

TEST(Mailbox, take_whenCalledAgain_waitsForTheNextPut) {
  Mailbox mailbox;
  mailbox.put(run_of("test.first"));
  EXPECT_EQ(mailbox.take(), run_of("test.first"));
  std::vector<Observation> taken;

  std::thread sender([&mailbox, &taken] { taken = mailbox.take(); });
  mailbox.put(run_of("test.second"));
  sender.join();

  EXPECT_EQ(taken, run_of("test.second"));
}

}  // namespace
}  // namespace rasp::plugins::reporting
