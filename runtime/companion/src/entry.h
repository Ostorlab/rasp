/// Whole-entry lifetime leases; publication cannot race a raw pointer load or provider replacement.
#pragma once

namespace rasp::keys {
class Service;
/// Fixed-size process registry lease covering the entire public/private native entry.
class EntryLease {
 public:
  /// Acquire a native read lease before loading the active owner; contention returns immediately.
  EntryLease();
  /// Drop the full-entry read/write lease; no UI entry waits for a writer.
  ~EntryLease();
  EntryLease(const EntryLease&) = delete;
  EntryLease& operator=(const EntryLease&) = delete;
  EntryLease(EntryLease&&) = delete;
  EntryLease& operator=(EntryLease&&) = delete;
  /// Protected stable owner or null for genuinely absent/platform-transition state.
  [[nodiscard]] Service* get() const;
  /// Separate writer contention from unavailable attachment.
  [[nodiscard]] bool busy() const;
  /// Drop the read lease and try exclusive ownership while the service state lock remains held.
  /// A failed upgrade cannot access the platform again; the stable service/mutex remains alive.
  [[nodiscard]] bool try_exclusive();
  /// Closing-worker-only native write barrier; closing state forbids detach/replacement across upgrade.
  /// Never called from a public/UI entry; no standard-library atomic waiter table is allocated.
  [[nodiscard]] bool wait_exclusive();

 private:
  Service* owner_ = nullptr;
  bool held_ = false;
  bool writer_ = false;
};
}  // namespace rasp::keys
