/// Fixed companion owner; never linked into the injected runtime or exposed as C++ ABI.
#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <variant>

#include "encoding.h"
#include "manifest.h"
#include "platform.h"

namespace rasp::keys {
class EntryLease;
/// One reserved request arena plus one reserved completion arena and finite metadata.
struct Request {
  RaspScopedKeySubmitV1 input{};
  RaspScopedKeyCompletionV1 result{};
  RaspScopedKeyTokenV1 token{};
  std::uint64_t deadline = 0;
  std::uint32_t targets = 0;
  std::array<RaspScopedKeyTokenV1, 8> target_ids{};
  std::uint32_t target_count = 0;
  std::uint32_t space = 0;
  std::uint32_t final_status = RASP_SK_OP_OK;
  std::uint32_t handle_slot = 16;
  bool used = false;
  bool terminal = false;
  bool taken = false;
  bool delivery = false;
  bool cleanup = false;
  std::atomic<bool> taking{false};
  std::atomic<std::uint64_t> delivery_prefix{0};
  std::atomic<std::uint64_t> delivery_ordinal{0};
};
/// Actual typed arenas stay below the frozen maxima; discriminator/slot bookkeeping is other state.
inline constexpr std::size_t kOwnedArenaBytes =
    (8 * (sizeof(RaspScopedKeySubmitV1) + sizeof(RaspScopedKeyCompletionV1))) + (std::size_t{2} * 8192);
static_assert(kOwnedArenaBytes == 71936 && kOwnedArenaBytes <= 98304);
/// Typed fields exactly partition one8192-byte arena; object representation also holds manifest bytes.
struct alignas(8) SigningScratch {
  std::array<std::uint8_t, 4960> message{};
  RaspLocalGateResultV1 gate{};
  std::array<std::uint8_t, 32> hash{};
  std::array<std::uint8_t, 72> signature{};
  std::array<std::uint8_t, 1024> context{};
};
static_assert(sizeof(SigningScratch) == 8192);
static_assert(offsetof(SigningScratch, gate) == 4960 && offsetof(SigningScratch, context) == 7168);
/// Two mutually exclusive arena phases; the finite variant discriminator counts as metadata.
using Scratch = std::variant<std::array<std::uint8_t, 8192>, SigningScratch>;
static_assert(sizeof(Scratch) <= 8200);
/// Each physical job permanently owns one8192-byte scratch/context lease until quiescent.
struct Job {
  Scratch scratch;
  KeyReference reference{};
  RaspScopedKeyInfoV1 measured{};
  RaspScopedKeyTokenV1 token{};
  std::uint32_t request = 0;
  std::uint32_t record = 32;
  bool used = false;
  bool running = false;
  bool posted = false;
  bool auth_pending = false;
  bool authenticated = false;
  bool yielded_for_auth = false;
  bool prompt = false;
  bool closing = false;
  bool cleanup = false;
};
/// Mutable unsigned-byte view of the owned trivially-copyable arena, never a borrowed external buffer.
[[nodiscard]] std::span<std::uint8_t, 8192> job_bytes(Job& job);
/// Finite handle lease; the persistent key record is not duplicated per handle.
struct Handle {
  RaspScopedKeyTokenV1 token{};
  RaspScopedKeyTokenV1 key_id{};
  RaspScopedKeyTokenV1 owner{};
  std::uint64_t expires = 0;
  bool used = false;
};
/// Namespace session identity and current canonical public profile.
struct Namespace {
  RaspScopedKeyTokenV1 token{};
  std::array<std::uint8_t, 32> profile{};
  bool resetting = false;
};
/// Small outside-lock post list; no scheduler or callback runs under the state lock.
struct Posts {
  std::array<RaspScopedKeyTokenV1, 2> jobs{};
  std::array<RaspScopedKeyTokenV1, 2> cancels{};
  std::size_t count = 0;
  std::size_t cancel_count = 0;
};
/// The single process-lifetime fixed state owner, with no abandoned-client chain.
class Service {
 public:
  /// Construct only after private adapter attachment in fixed aligned storage.
  explicit Service(Platform& platform) : platform_(&platform) {}
  /// Actual public open; performs worker-only owned storage initialization.
  [[nodiscard]] std::int32_t open(const RaspScopedKeyClientSpecV1& input, RaspScopedKeyClientOpenedV1& output);
  /// Copy validated input into one reserved arena and dispatch bounded jobs.
  [[nodiscard]] std::int32_t submit(const RaspScopedKeySubmitV1& input, RaspScopedKeyAdmissionV1& output);
  /// Transfer at most one owned result, with fresh gate and lifetime checks.
  [[nodiscard]] std::int32_t take(const RaspScopedKeyTakeRequestV1& input, RaspScopedKeyTakeResultV1& output);
  /// Cancel/release/close without waiting for provider quiescence.
  [[nodiscard]] std::int32_t control(const RaspScopedKeyControlV1& input, RaspScopedKeyControlResultV1& output);
  /// Child executor consumes only its exact already reserved token.
  void run(const RaspScopedKeyTokenV1& value, EntryLease& entry);
  /// Request-local callback cannot grant authority to another job or key.
  void auth(const RaspScopedKeyTokenV1& value, std::uint32_t status, const PlatformDiagnostic& diagnostic,
            const PromptCheck* refused_prompt);
  /// Copy immutable binding then revalidate the exact still-owned job after external gate/clock calls.
  [[nodiscard]] std::uint32_t prompt_eligibility(const RaspScopedKeyTokenV1& value, PromptCheck& check);
  /// Reserve the original request slot while an owned wrapper callback runs.
  [[nodiscard]] bool reserve_delivery(const RaspScopedKeyTokenV1& value);
  /// Only never-destroyed atomic slots/counters are accessed; no platform, mutex or descriptor access.
  [[nodiscard]] bool acknowledge_delivery(const RaspScopedKeyTokenV1& value);
  /// Atomic-only notification check, safe through the permanently published stable owner.
  [[nodiscard]] bool delivery_pending() const;
  /// Nonblocking bounded fold/post, called only while a native read lease pins the installed platform.
  void drain_delivery();
  /// Attachment cannot be replaced until every old borrower is quiescent.
  [[nodiscard]] bool detach(Platform& platform, EntryLease& entry);
  /// Reattach the same process-stable owner only under an exclusive registry lease.
  [[nodiscard]] bool reattach(Platform& platform);

 private:
  /// One exclusive service lifecycle, independent of client handles.
  enum class State : std::uint8_t { kIdle, kOpening, kReady, kClosing, kClosed };
  /// Sample the external clock outside the state lock; contention is BUSY, never guessed time.
  [[nodiscard]] bool refresh_clock();
  /// Consume/latch the most recent serialized external clock sample under the state lock.
  [[nodiscard]] bool sample(std::uint64_t& now);
  /// Fresh public tokens combine CSPRNG bytes and a process-monotonic nonwrapping allocation ordinal.
  [[nodiscard]] bool token(RaspScopedKeyTokenV1& output);
  /// Initialize immutable binding and validate/load or durably create its manifest.
  [[nodiscard]] std::uint32_t load();
  /// Compute immutable application/profile hashes without touching storage bytes.
  [[nodiscard]] std::uint32_t profiles(std::span<std::uint8_t, 32> app_hash);
  /// Validate every loaded record and the per-namespace key ceiling before cleanup.
  [[nodiscard]] bool valid_loaded() const;
  /// Recover only durable reserved/tombstoned identities; uncertain writes latch the client.
  [[nodiscard]] std::uint32_t recover(std::span<std::uint8_t> scratch);
  /// Persist a complete candidate before atomically adopting it in memory.
  [[nodiscard]] std::uint32_t persist(Job& job);
  /// Return namespace/record/handle index or its finite sentinel.
  [[nodiscard]] std::size_t namespace_index(const RaspScopedKeyTokenV1& value) const;
  [[nodiscard]] std::size_t record_index(const RaspScopedKeyTokenV1& value) const;
  [[nodiscard]] std::size_t handle_index(const RaspScopedKeyTokenV1& value) const;
  /// Refuse namespace operations while exact durable cleanup is pending.
  [[nodiscard]] bool pending(std::uint32_t space) const;
  /// Set a complete failure projection without freeing physical borrowers.
  void fail(Request& request, std::uint32_t status);
  /// Destroy a taken request only when jobs, native copies and callbacks no longer borrow it.
  void retire(std::size_t index);
  /// Caller holds the state mutex and has authenticated the client; snapshot physically retained slots.
  template <typename Output>
  void snapshot_retained(Output& output) const;
  /// Fold atomically acknowledged callback returns into the bounded tables on next state access.
  void drain_releases();
  /// Select at most two jobs while holding the state lock; return copied post identities.
  void dispatch(Posts& posts);
  /// Invoke child scheduler/cancel outside the state lock; scheduling failure stays failure.
  void post(const Posts& posts);
  /// Copy exact manifest/config metadata into a job-owned immutable key reference.
  void reference(Job& job, const RaspScopedKeyTokenV1& key, std::uint32_t space);
  /// Invalidate affected handles and pending uses immediately, independently of persistence.
  void invalidate(const Request& subject, Posts& posts);
  /// Resolve an operation's exact target and semantic binding before reservation.
  [[nodiscard]] std::uint32_t resolve(const RaspScopedKeySubmitV1& input, std::uint64_t now, std::size_t& record) const;
  /// Reserve no state until both request/handle/key capacities have been checked.
  [[nodiscard]] std::uint32_t capacity(const RaspScopedKeySubmitV1& input, std::size_t space,
                                       std::size_t& handle_slot) const;
  /// Capture immutable cleanup identities and apply immediate invalidation under the state lock.
  [[nodiscard]] bool targets(Request& request, std::size_t record, Posts& posts);
  /// Apply a validated control under the state lock; posting remains outside it.
  void apply_control(const RaspScopedKeyControlV1& input, RaspScopedKeyControlResultV1& output);
  /// Determine scheduling eligibility without reserving a physical lease.
  [[nodiscard]] bool dispatchable(const Request& request, std::size_t index) const;
  /// Reserve and initialize one available bounded physical job.
  [[nodiscard]] bool reserve_job(Job& job, Request& request, std::size_t index, Posts& posts);
  /// Determine whether this request needs the single prompt lease.
  [[nodiscard]] bool needs_prompt(const Request& request) const;
  /// Match only immutable copied identities; caller holds state lock, including on refusal consumption.
  [[nodiscard]] bool matches_prompt(const Job& job, const PromptSnapshot& snapshot) const;
  /// Exact active prompt eligibility, never matched by key or recycled slot alone; state lock held.
  [[nodiscard]] std::uint32_t prompt_status(const Job& job, std::uint64_t now) const;
  /// Copy the immutable gate operation/hash; caller owns the destination and holds the state lock.
  void gate_input(std::uint32_t space_index, RaspLocalGateRequestV1& input) const;
  /// Preserve latest meaningful actual OS failure; invalid private diagnostics fail closed.
  [[nodiscard]] std::uint32_t boundary(Job& job, std::uint32_t status, const PlatformDiagnostic& diagnostic);
  /// Actual gate receives only immutable operation/hash, never a host-supplied decision.
  [[nodiscard]] bool gate(const Request& request, RaspLocalGateResultV1& output) const;
  /// Check request/handle lease, cancel, current record identity and namespace before key use.
  [[nodiscard]] std::uint32_t eligible(const Request& request, std::uint64_t now) const;
  /// Persistent public identity uses full128-bit CSPRNG output, with at most four collision attempts.
  [[nodiscard]] std::uint32_t fresh_key_id(RaspScopedKeyTokenV1& output);
  /// Recheck lookup/lifetime and actual gate immediately before committing an auth prompt.
  [[nodiscard]] std::uint32_t prepare_auth(Job& job);
  /// Generate once and durably retain only its canonical owned witness before live promotion.
  [[nodiscard]] std::uint32_t generate(Job& job, CleanupProof& proof);
  /// Describe/revalidate and start the existing early/later authentication handshake when required.
  [[nodiscard]] std::uint32_t start_auth(Job& job);
  /// Complete worker phases through actual adapter operations.
  [[nodiscard]] std::uint32_t create(Job& job);
  [[nodiscard]] std::uint32_t describe(Job& job);
  [[nodiscard]] std::uint32_t sign(Job& job);
  [[nodiscard]] std::uint32_t erase(Job& job);
  /// Publish one terminal result and release physical/context ownership exactly once.
  void finish(Job& job, std::uint32_t status);
  /// Perform final bounded storage flush/close on a worker, retaining owner on failure.
  void close(Job& job, EntryLease& entry);
  /// Expose truthful bounded progress while a physical job retains its request.
  void progress(Job& job, RaspScopedKeyDurabilityV1 durability, RaspScopedKeyEffectV1 effect);
  /// Remove a cancelled/failed creation using its already durable exact reservation.
  [[nodiscard]] std::uint32_t cleanup_created(Job& job, const CleanupProof& proof);
  /// Allocate a finite memory lease after a fully verified successful key operation.
  [[nodiscard]] bool handle(Request& request, const RaspScopedKeyInfoV1& info, std::uint64_t now);

  Platform* platform_;
  std::mutex mutex_;
  State state_ = State::kIdle;
  RaspScopedKeyClientSpecV1 config_{};
  Application application_{};
  Manifest manifest_{};
  Manifest candidate_{};
  std::array<Request, 8> requests_{};
  std::array<Job, 2> jobs_{};
  std::array<Handle, 16> handles_{};
  std::array<Namespace, 4> namespaces_{};
  std::array<bool, 32> blocked_{};
  RaspScopedKeyTokenV1 client_{};
  RaspScopedKeyTokenV1 last_closed_{};
  std::uint64_t last_tick_ = 0;
  std::atomic<std::uint32_t> native_borrowers_{0};
  std::atomic<std::uint64_t> delivery_released_{0};
  std::atomic<std::uint64_t> delivery_drained_{0};
  std::atomic<std::uint64_t> sampled_tick_{0};
  std::atomic<bool> sampled_valid_{false};
  std::atomic<bool> sampled_fault_{false};
  std::atomic_flag clock_reader_ = ATOMIC_FLAG_INIT;
  std::array<std::uint8_t, 8> entropy_{};
  bool clock_seen_ = false;
  bool clock_fault_ = false;
  bool mutation_ = false;
  bool prompt_ = false;
  bool storage_owned_ = false;
  bool storage_fault_ = false;
};
static_assert(sizeof(Service) + 4096 + 128 <= 131072);
}  // namespace rasp::keys
