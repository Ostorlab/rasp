/// Mailbox: the one-batch hand-off between the runtime's thread and the plugin's sender.

#include "mailbox.h"

#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace rasp::plugins::dns_reporting {

void Mailbox::put(std::vector<std::string> names) {
  std::optional<std::vector<std::string>> dropped;
  {
    const std::scoped_lock lock(mutex_);
    dropped.swap(batch_);
    batch_ = std::move(names);
  }
  ready_.notify_one();
}

std::vector<std::string> Mailbox::take() {
  std::unique_lock lock(mutex_);
  ready_.wait(lock, [this] { return batch_.has_value(); });
  std::vector<std::string> names = std::move(batch_).value_or(std::vector<std::string>{});
  batch_.reset();
  return names;
}

}  // namespace rasp::plugins::dns_reporting
