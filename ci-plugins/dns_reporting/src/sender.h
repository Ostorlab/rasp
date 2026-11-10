/// The DNS reporting plugin's sender: its own thread, which resolves the DNS query names of the newest run.

#pragma once

#include <string>
#include <vector>

#include "mailbox.h"

namespace rasp::plugins::dns_reporting {

/// A function that resolves one DNS name, with the shape of the platform's `resolve`.
using ResolveFunction = bool (*)(const std::string& name) noexcept;

/// Everything the sender's thread needs. It lives as long as the process once the thread has started.
struct Sender {
  /// The function that resolves a DNS name: the platform's `resolve`.
  ResolveFunction resolve = nullptr;
  /// The batch of DNS names waiting to be resolved.
  Mailbox mailbox;
};

/// Resolves all the DNS query names of one batch. Stops on the first failure.
///
/// @param sender The sender.
/// @param names The DNS names to resolve.
/// @return `true` when every name resolved.
[[nodiscard]] bool deliver(const Sender& sender, const std::vector<std::string>& names);

/// Starts the sender's thread: a detached thread with a 512 KiB stack that takes each batch from the mailbox and
/// delivers it, until the process exits.
///
/// @param sender The sender. It must live as long as the process.
/// @return Whether the thread started.
[[nodiscard]] bool start_sender(Sender& sender);

}  // namespace rasp::plugins::dns_reporting
