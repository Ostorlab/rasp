/// Mailbox: hands the DNS query names of a run from the runtime's thread to the plugin's sender.

#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace rasp::plugins::dns_reporting {

/// Holds at most one batch of DNS names until the sender takes it.
///
/// Every method is safe to call from any thread. `put` never waits for the sender: it holds the lock only to swap the
/// batch in.
class Mailbox {
 public:
  /// Leaves a batch for the sender. A batch the sender hasn't taken yet is dropped: only the newest is kept.
  ///
  /// @param names The DNS query names.
  void put(std::vector<std::string> names);

  /// Waits until a batch is there, then takes it.
  ///
  /// @return The batch, which the mailbox no longer holds.
  [[nodiscard]] std::vector<std::string> take();

 private:
  std::mutex mutex_;
  std::condition_variable ready_;
  std::optional<std::vector<std::string>> batch_;
};

}  // namespace rasp::plugins::dns_reporting
