/// Mailbox: hands the observations of a run from the runtime's thread to the plugin's sender, keeping only the newest.

#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins::reporting {

/// Holds at most one run, all its observations, until the sender takes it.
///
/// Every method is safe to call from any thread. `put` never waits for the sender: it holds the lock only to replace
/// the run.
class Mailbox {
 public:
  /// Leaves a run for the sender. A run the sender hasn't taken yet is dropped: only the newest is kept.
  ///
  /// @param run All the observations of the run.
  void put(std::vector<Observation> run);

  /// Waits until a run is there, then takes it.
  ///
  /// @return All the observations of the run, which the mailbox no longer holds.
  [[nodiscard]] std::vector<Observation> take();

 private:
  /// Guards `run_`.
  std::mutex mutex_;
  /// Signalled when a run is put.
  std::condition_variable ready_;
  /// The run waiting for the sender, if any.
  std::optional<std::vector<Observation>> run_;
};

}  // namespace rasp::plugins::reporting
