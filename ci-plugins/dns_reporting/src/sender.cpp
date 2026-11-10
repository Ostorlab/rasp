/// deliver and start_sender: the DNS reporting plugin's sender thread.

#include "sender.h"

#include <cstddef>
#include <pthread.h>
#include <string>
#include <vector>

#include "rasp/util/logging.h"

namespace rasp::plugins::dns_reporting {

namespace {

/// The stack size of the sender's thread.
constexpr std::size_t kStackSize = std::size_t{512} * 1024;

/// The thread: takes each batch from the mailbox and delivers it.
void* run(void* argument) {
  auto* const sender = static_cast<Sender*>(argument);
  while (true) {
    const std::vector<std::string> names = sender->mailbox.take();
    static_cast<void>(deliver(*sender, names));
  }
}

}  // namespace

bool deliver(const Sender& sender, const std::vector<std::string>& names) {
  if (sender.resolve == nullptr) {
    return false;
  }
  for (const std::string& name : names) {
    if (!sender.resolve(name)) {
      if constexpr (kLoggingEnabled) {
        rasp::log("dns_reporting: resolve failed, remaining names dropped");
      }
      return false;
    }
  }
  if constexpr (kLoggingEnabled) {
    rasp::log("dns_reporting: resolved " + std::to_string(names.size()) + " DNS names");
  }
  return true;
}

bool start_sender(Sender& sender) {
  pthread_attr_t attributes{};  // NOLINT(misc-include-cleaner)
  if (pthread_attr_init(&attributes) != 0) {
    return false;
  }
  bool started = false;
  if (pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0 &&
      pthread_attr_setstacksize(&attributes, kStackSize) == 0) {
    pthread_t thread{};  // NOLINT(misc-include-cleaner)
    started = pthread_create(&thread, &attributes, run, &sender) == 0;
  }
  static_cast<void>(pthread_attr_destroy(&attributes));
  return started;
}

}  // namespace rasp::plugins::dns_reporting
