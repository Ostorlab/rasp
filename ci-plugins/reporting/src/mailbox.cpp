/// Mailbox: the one-run hand-off between the runtime's thread and the plugin's sender.

#include "mailbox.h"

#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins::reporting {

void Mailbox::put(std::vector<Observation> run) {
  {
    const std::scoped_lock lock(mutex_);
    run_ = std::move(run);
  }
  ready_.notify_one();
}

std::vector<Observation> Mailbox::take() {
  std::unique_lock lock(mutex_);
  ready_.wait(lock, [this] { return run_.has_value(); });
  std::vector<Observation> run = std::move(run_).value_or(std::vector<Observation>{});
  run_.reset();
  return run;
}

}  // namespace rasp::plugins::reporting
