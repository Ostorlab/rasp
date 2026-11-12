/// Private worker-owned policy service, bounded publication and process-lifetime installation.
#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "rasp/config.h"
#include "rasp/cycle.h"
#include "rasp/local_policy_host.h"

namespace rasp {
/// Checked suspend-inclusive nanoseconds in this process; missing means unavailable.
[[nodiscard]] std::optional<std::int64_t> read_local_policy_clock();
/// Policy owner used only inside the runtime; no C++ object crosses a host ABI.
class LocalPolicyState {
 public:
  /// Copy and validate worker configuration before publishing any raw service pointer.
  explicit LocalPolicyState(Config config, std::string platform,
                            std::optional<std::int64_t> (*clock)() = read_local_policy_clock);
  /// Begin a finite cycle; called before actual builtin measurement, never by a host.
  void begin_cycle();
  /// Publish the exact immutable completed owner before plugin callbacks.
  void finish_cycle(std::shared_ptr<const CycleSnapshot> snapshot);
  /// Copy configuration into caller memory; no owner or borrowed reference escapes.
  [[nodiscard]] std::int32_t info(struct RaspLocalPolicyInfoV1& output) const;
  /// Evaluate one historical typed owner and copy out a complete immutable decision projection.
  [[nodiscard]] std::int32_t gate(const struct RaspLocalGateRequestV1& request, struct RaspLocalGateResultV1& output);

 private:
  /// Advance the shared checked clock and latch every detected failure/regression.
  [[nodiscard]] std::optional<std::int64_t> sample_clock();
  /// Final parsed effective configuration, including tri-state collection selection.
  const Config config_;
  /// Actual compiled target, independent of caller-provided policy platform.
  const std::string platform_;
  /// Equality hashes are computed once on the monitoring worker.
  const std::string policy_hash_;
  const std::string config_hash_;
  /// No host input can substitute this clock function.
  std::optional<std::int64_t> (*clock_)();
  /// Protects primitive clock health and owner copying only; gate uses try_lock once.
  std::mutex mutex_;
  /// Admission caps actual retained native owners at eight in-flight gate calls.
  std::atomic<std::uint32_t> readers_{0};
  /// One owned publication; replacement destruction happens outside the lock.
  std::shared_ptr<const CycleSnapshot> snapshot_;
  /// Ordered private samples; no telemetry/wall-time inference.
  std::optional<std::int64_t> last_tick_;
  std::optional<std::int64_t> start_;
  std::optional<std::int64_t> published_start_;
  std::optional<std::int64_t> published_end_;
  /// Fault generations never wrap; a gate read cannot clear a publication fault.
  std::uint64_t faults_ = 0;
  std::uint64_t start_faults_ = 0;
  std::uint64_t published_faults_ = 0;
  bool exhausted_ = false;
};
/// Install once, intentionally retaining one bounded service for process lifetime.
/// @param state Unique initialized owner; release only after successful atomic installation.
/// @return Installed pointer, or null for a duplicate; there is no replacement/reset API.
[[nodiscard]] LocalPolicyState* install_local_policy(std::unique_ptr<LocalPolicyState> state);
/// Load the process-lifetime owner with acquire ordering; null until initialization.
[[nodiscard]] LocalPolicyState* process_local_policy();
}  // namespace rasp
