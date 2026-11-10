/// handshake off iOS: the pin probe runs only on an iPhone for now, so here it can't run.

#include "handshake.h"

#include <chrono>
#include <string>

namespace rasp::plugins::adr_pin {

Handshake handshake(const std::string& host, std::chrono::milliseconds timeout) {
  static_cast<void>(host);
  static_cast<void>(timeout);
  return Handshake{.outcome = Outcome::kUnsupported, .chain = {}, .trusted = false};
}

}  // namespace rasp::plugins::adr_pin
