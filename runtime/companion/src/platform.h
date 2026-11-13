/// Private child-adapter boundary; not installed, exported, or a host auth/decision override.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "encoding.h"
#include "rasp/local_policy_host.h"
#include "rasp/scoped_key.h"

namespace rasp::keys {
/// Child SDK state must fit this one process-stable4KiB reservation; OS objects remain separately bounded.
[[nodiscard]] std::span<std::byte, 4096> platform_storage();
/// Immutable identity copied per physical job; never an arbitrary alias supplied by the caller.
struct KeyReference {
  RaspScopedKeyTokenV1 generation{};
  RaspScopedKeyTokenV1 key_id{};
  RaspScopedKeyNamespaceSpecV1 space{};
  std::array<std::uint8_t, 32> profile_sha256{};
};
/// Optional bounded OS diagnostic, never an authority decision or borrowed OS object.
struct PlatformDiagnostic {
  std::uint32_t present{};
  RaspScopedKeyPlatformErrorV1 error{};
};
/// Only an actually fresh generated point establishes creation ownership.
enum class CreationClaim : std::uint8_t { kUnproved = 0, kNoCreation = 1, kFreshPoint = 2 };
struct alignas(4) CreationReceipt {
  CreationClaim claim{};
  std::array<std::uint8_t, 3> reserved{};
  std::array<std::uint8_t, 65> point{};
};
/// Absence alone may retire an unproved reservation; occupied aliases require an exact witness.
enum class CleanupMode : std::uint8_t { kAbsentOnly = 0, kMatchCreatedPoint = 1 };
struct alignas(4) CleanupProof {
  CleanupMode mode{};
  std::array<std::uint8_t, 3> reserved{};
  std::array<std::uint8_t, 65> point{};
};
/// Immutable copied identity/binding; no Service pointers cross an unlocked gate or clock call.
struct PromptSnapshot {
  RaspScopedKeyTokenV1 job{}, request{}, client{}, generation{}, key{}, handle{}, namespace_handle{};
  std::array<std::uint8_t, 32> profile{};
  RaspLocalGateRequestV1 gate_request{};
  std::uint32_t gate_mode{};
};
/// Owned serialized adapter scratch, retained through any worker-side refusal acknowledgment.
struct PromptCheck {
  PromptSnapshot snapshot{};
  RaspLocalGateResultV1 gate{};
  std::uint32_t gate_present{};
  std::int32_t gate_call_status{};
  std::uint32_t operation_status{};
  std::uint32_t gate_committed{};
};
static_assert(sizeof(PlatformDiagnostic) == 32 && alignof(PlatformDiagnostic) == 8);
static_assert(sizeof(CreationReceipt) == 72 && sizeof(CleanupProof) == 72);
static_assert(sizeof(PromptSnapshot) == 264 && sizeof(PromptCheck) == 2384);
/// Closed canonical diagnostic vocabulary; absence cannot hide nonzero payload bytes.
[[nodiscard]] bool valid_diagnostic(const PlatformDiagnostic& diagnostic);
/// Derive only exact witnessed cleanup or conservative absence-only cleanup.
[[nodiscard]] CleanupProof cleanup_proof(const RaspScopedKeyInfoV1& info);
/// Owned adapter implemented inside the companion by HD06/HD07; all statuses use OP vocabulary.
class Platform {
 public:
  Platform() = default;
  Platform(const Platform&) = delete;
  Platform& operator=(const Platform&) = delete;
  Platform(Platform&&) = delete;
  Platform& operator=(Platform&&) = delete;
  virtual ~Platform() = default;
  /// Main-thread detection must not wait, perform I/O, or infer a fake UI owner.
  [[nodiscard]] virtual bool main_thread() = 0;
  /// Bounded CSPRNG access; fail rather than produce a predictable fallback.
  [[nodiscard]] virtual bool random(std::span<std::uint8_t> output) = 0;
  /// Nonblocking checked suspend-inclusive native ticks; no JNI, I/O, wait or wall-clock substitute.
  [[nodiscard]] virtual bool clock(std::uint64_t& nanoseconds) = 0;
  /// Acquire/retain exclusive owned private storage and return exact file bytes or absence.
  [[nodiscard]] virtual std::uint32_t open_storage(Application& app, std::span<std::uint8_t> file,
                                                   std::uint32_t& written, bool& exists) = 0;
  /// OK acknowledges file+rename+directory durability; every other return is uncertain publication.
  [[nodiscard]] virtual std::uint32_t persist(std::span<const std::uint8_t> file, PlatformDiagnostic& diagnostic) = 0;
  /// Worker-only close; false keeps the one closing service and blocks replacement opens.
  [[nodiscard]] virtual bool close_storage() = 0;
  /// Post one of at most two reserved jobs; never invoke run_job inline.
  [[nodiscard]] virtual bool schedule(const RaspScopedKeyTokenV1& job) = 0;
  /// Generate only the exact scoped/profiled key; return actual public key/provenance in measured.
  [[nodiscard]] virtual std::uint32_t create(const KeyReference& key, RaspScopedKeyInfoV1& measured,
                                             CreationReceipt& receipt, PlatformDiagnostic& diagnostic) = 0;
  /// Read the exact existing key; missing returns NOT_FOUND, never regeneration.
  [[nodiscard]] virtual std::uint32_t describe(const KeyReference& key, RaspScopedKeyInfoV1& measured,
                                               PlatformDiagnostic& diagnostic) = 0;
  /// Retain request-local crypto/auth state in this fixed context or bounded OS references.
  [[nodiscard]] virtual std::uint32_t authenticate(const RaspScopedKeyTokenV1& job, const KeyReference& key,
                                                   std::span<std::uint8_t> context, PlatformDiagnostic& diagnostic) = 0;
  /// Initialize/update the exact crypto object and preallocate output; never invoke the primitive.
  [[nodiscard]] virtual std::uint32_t prepare_sign(const KeyReference& key, std::span<const std::uint8_t> message,
                                                   std::span<std::uint8_t> context, PlatformDiagnostic& diagnostic) = 0;
  /// Only the already-prepared primitive; no message feeding, lookup or initialization after the final gate.
  [[nodiscard]] virtual std::uint32_t sign(const KeyReference& key, std::span<std::uint8_t> context,
                                           std::span<std::uint8_t> der, std::uint32_t& written,
                                           PlatformDiagnostic& diagnostic) = 0;
  /// Exact absence or matching generated point only; occupied/unreadable/mismatched proof stays pending.
  [[nodiscard]] virtual std::uint32_t erase(const KeyReference& key, const CleanupProof& proof,
                                            PlatformDiagnostic& diagnostic) = 0;
  /// Request-specific nonblocking cancellation; provider still owes quiescence.
  virtual void cancel(const RaspScopedKeyTokenV1& job) = 0;
  /// Worker-only release of all context borrowers; no later callback may use the old crypto object.
  virtual void release(std::span<std::uint8_t> context) = 0;
};
/// Link-private platform installation; caller must retain adapter until detach succeeds.
[[nodiscard]] bool attach_platform(Platform& platform);
/// Detach only after fully closed/quiescent; never frees an in-flight callback owner.
[[nodiscard]] bool detach_platform(Platform& platform);
/// Executor entry for a previously reserved job, from one of two fixed child workers.
/// Worker read leases wait through registry writers; do not invoke from an OS/UI callback queue.
void run_job(const RaspScopedKeyTokenV1& job);
/// Worker-side auth acknowledgment; OS/UI callbacks post only copied IDs to the two fixed workers.
/// Stale/full-token mismatch never resumes crypto; adapter release drains every context borrower.
void authenticated(const RaspScopedKeyTokenV1& job, std::uint32_t status);
/// Explicit actual diagnostic/refusal channel; optional payload never grants authentication.
void authenticated(const RaspScopedKeyTokenV1& job, std::uint32_t status, const PlatformDiagnostic& diagnostic,
                   const PromptCheck* refused_prompt = nullptr);
/// UI-safe once-only prompt check; BUSY is terminal refusal, never auth success or a retry permit.
[[nodiscard]] std::uint32_t prompt_eligibility(const RaspScopedKeyTokenV1& job, PromptCheck& check);
/// Trusted wrapper must reserve its original request slot before take/delivery.
[[nodiscard]] bool begin_delivery(const RaspScopedKeyTokenV1& request);
/// Release the exact committed wrapper lease after its callback has returned.
/// This UI-safe entry durably acknowledges through permanent atomic slots, even during registry writes.
void end_delivery(const RaspScopedKeyTokenV1& request);
}  // namespace rasp::keys
