/// Admission, owned results, clocks and the exclusive bounded companion lifecycle.
#include "service.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <span>
#include <string_view>
#ifdef __GLIBC__
#include <bits/pthreadtypes.h>
#endif

#include "encoding.h"
#include "entry.h"
#include "manifest.h"
#include "platform.h"
#include "rasp/local_policy_host.h"
#include "rasp/scoped_key.h"

namespace rasp::keys {
namespace {
/// All mutable process ownership, entry counters and child storage are one bounded allocation.
struct Registry {
  std::optional<Service> owner;
  alignas(std::max_align_t) std::array<std::byte, 4096> adapter_state{};
  std::atomic<Service*> installed{nullptr};
  std::atomic<Service*> stable{nullptr};
  pthread_rwlock_t entries = PTHREAD_RWLOCK_INITIALIZER;
  std::atomic<std::uint64_t> ordinal{0};
};
static_assert(sizeof(Registry) <= 131072);
static_assert(sizeof(Registry) - kOwnedArenaBytes <= 32768);
/// Constinit has no load constructor; no_destroy explicitly preserves the one owner/mutex through process exit.
/// Its native descriptors/platform are separately closed and detached under exclusive entry quiescence.
Registry& registry() {
  [[clang::no_destroy]] static constinit Registry state{};
  return state;
}
/// No recursion/extra jobs: pin a native read lease before a bounded atomic-release fold/post.
void drain_delivery_acknowledgments() {
  const Service* stable = registry().stable.load(std::memory_order_acquire);
  if (stable == nullptr || !stable->delivery_pending() || pthread_rwlock_tryrdlock(&registry().entries) != 0) {
    return;
  }
  Service* owner = registry().installed.load(std::memory_order_acquire);
  if (owner != nullptr) {
    owner->drain_delivery();
  }
  static_cast<void>(pthread_rwlock_unlock(&registry().entries));
}
/// Client+namespace allocation precede every request, so request ordinal1 is permanently unissued.
constexpr std::uint64_t kDeliveryCommitting = 1;
/// Volatile stores prevent elision after a request slot becomes logically unreachable.
template <typename Value>
void wipe_object(Value& value) {
  for (volatile auto& byte : std::as_writable_bytes(std::span(&value, 1))) {
    byte = std::byte{};
  }
}
/// Typed output initialization never creates an operation success.
void result_header(Request& request) {
  request.result = {};
  request.result.abi_version = 1;
  request.result.struct_size = sizeof(request.result);
  request.result.operation = request.input.operation;
  request.result.request = request.token;
}
/// Bounded bitmask over the manifest's32 owned slots.
std::uint32_t bit(std::size_t index) { return UINT32_C(1) << index; }
}  // namespace
EntryLease::EntryLease(EntryAccess access) {
  const auto status = access == EntryAccess::kWorkerWait ? pthread_rwlock_rdlock(&registry().entries)
                                                         : pthread_rwlock_tryrdlock(&registry().entries);
  if (status != 0) {
    return;
  }
  held_ = true;
  owner_ = registry().installed.load(std::memory_order_acquire);
}
EntryLease::~EntryLease() {
  if (held_ || writer_) {
    static_cast<void>(pthread_rwlock_unlock(&registry().entries));
    drain_delivery_acknowledgments();
  }
}
Service* EntryLease::get() const { return owner_; }
bool EntryLease::busy() const { return !held_ && !writer_; }
bool EntryLease::try_exclusive() {
  if (writer_) {
    return true;
  }
  if (held_) {
    static_cast<void>(pthread_rwlock_unlock(&registry().entries));
    held_ = false;
  }
  writer_ = pthread_rwlock_trywrlock(&registry().entries) == 0;
  return writer_;
}
bool EntryLease::wait_exclusive() {
  if (!try_exclusive()) {
    writer_ = pthread_rwlock_wrlock(&registry().entries) == 0;
  }
  return writer_;
}
std::span<std::byte, 4096> platform_storage() { return registry().adapter_state; }
bool attach_platform(Platform& platform) {
  if (pthread_rwlock_trywrlock(&registry().entries) != 0) {
    return false;
  }
  bool ready = false;
  if (registry().installed.load(std::memory_order_acquire) == nullptr) {
    Service* owner = nullptr;
    auto& slot = registry().owner;
    if (!slot.has_value()) {
      owner = &slot.emplace(platform);
      registry().stable.store(owner, std::memory_order_release);
      ready = true;
    } else {
      owner = &*slot;
      ready = owner->reattach(platform);
    }
    if (ready) {
      registry().installed.store(owner, std::memory_order_release);
    }
  }
  static_cast<void>(pthread_rwlock_unlock(&registry().entries));
  drain_delivery_acknowledgments();
  return ready;
}
bool detach_platform(Platform& platform) {
  EntryLease entry;
  Service* owner = entry.get();
  const bool ready = owner != nullptr && owner->detach(platform, entry);
  if (ready) {
    registry().installed.store(nullptr, std::memory_order_release);
  }
  return ready;
}
bool Service::detach(Platform& platform, EntryLease& entry) {
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock() || (state_ != State::kIdle && state_ != State::kClosed) || platform_ != &platform ||
      storage_owned_ || native_borrowers_.load() != 0 || !entry.try_exclusive()) {
    return false;
  }
  platform_ = nullptr;
  return true;
}
bool Service::reattach(Platform& platform) {
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock() || platform_ != nullptr || (state_ != State::kIdle && state_ != State::kClosed)) {
    return false;
  }
  platform_ = &platform;
  return true;
}
bool Service::token(RaspScopedKeyTokenV1& output) {
  output = {};
  std::ranges::copy(entropy_, std::span(output.bytes).begin());
  std::uint64_t current = registry().ordinal.load(std::memory_order_relaxed);
  for (std::size_t attempt = 0; attempt < 4; ++attempt) {
    if (current == std::numeric_limits<std::uint64_t>::max()) {
      output = {};
      return false;
    }
    if (registry().ordinal.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) {
      const std::uint64_t allocation = current + 1;
      std::memcpy(std::span(output.bytes).subspan(8).data(), &allocation, sizeof(allocation));
      return true;
    }
  }
  output = {};
  return false;
}
bool Service::refresh_clock() {
  if (clock_reader_.test_and_set(std::memory_order_acquire)) {
    return false;
  }
  std::uint64_t now = 0;
  const bool valid = platform_->clock(now);
  if (!valid || (sampled_valid_.load() && now < sampled_tick_.load())) {
    sampled_fault_.store(true, std::memory_order_release);
  }
  sampled_tick_.store(now, std::memory_order_release);
  sampled_valid_.store(valid, std::memory_order_release);
  clock_reader_.clear(std::memory_order_release);
  return true;
}
bool Service::sample(std::uint64_t& now) {
  now = sampled_tick_.load(std::memory_order_acquire);
  if (now > std::numeric_limits<std::uint64_t>::max() - UINT64_C(300000000000) || clock_fault_ ||
      sampled_fault_.load(std::memory_order_acquire) || !sampled_valid_.load(std::memory_order_acquire) ||
      (clock_seen_ && now < last_tick_)) {
    clock_fault_ = true;
    for (auto& handle : handles_) {
      handle.used = false;
    }
    for (auto& request : requests_) {
      if (request.used && !request.taken) {
        fail(request, RASP_SK_OP_CLOCK_UNAVAILABLE);
      }
    }
    return false;
  }
  last_tick_ = now;
  clock_seen_ = true;
  return true;
}
std::size_t Service::namespace_index(const RaspScopedKeyTokenV1& value) const {
  for (std::size_t index = 0; index < config_.namespace_count; ++index) {
    if (same(std::span{namespaces_}[index].token, value)) {
      return index;
    }
  }
  return 4;
}
std::size_t Service::record_index(const RaspScopedKeyTokenV1& value) const {
  for (std::size_t index = 0; index < manifest_.records.size(); ++index) {
    if (std::span{manifest_.records}[index].state != KeyState::kEmpty &&
        same(std::span{manifest_.records}[index].info.key_id, value)) {
      return index;
    }
  }
  return 32;
}
std::size_t Service::handle_index(const RaspScopedKeyTokenV1& value) const {
  if (!nonzero(value)) {
    return 16;
  }
  for (std::size_t index = 0; index < handles_.size(); ++index) {
    if (std::span{handles_}[index].used && same(std::span{handles_}[index].token, value)) {
      return index;
    }
  }
  return 16;
}
bool Service::pending(std::uint32_t space) const {
  if (std::span{namespaces_}[space].resetting) {
    return true;
  }
  const auto selector = std::span(config_.namespaces)[space].selector;
  for (std::size_t index = 0; index < manifest_.records.size(); ++index) {
    const auto& record = std::span{manifest_.records}[index];
    if (record.state != KeyState::kEmpty && record.info.namespace_selector == selector &&
        (std::span{blocked_}[index] || record.state != KeyState::kLive)) {
      return true;
    }
  }
  return false;
}
void Service::fail(Request& request, std::uint32_t status) {
  request.final_status = status;
  request.terminal = true;
  request.result.operation_status = status;
  if (request.result.value_tag != RASP_SK_VALUE_DELETION) {
    request.result.value = {};
    request.result.value_tag = RASP_SK_VALUE_NONE;
  }
  if (request.handle_slot < handles_.size() && same(std::span{handles_}[request.handle_slot].owner, request.token)) {
    std::span{handles_}[request.handle_slot].used = false;
  }
  if (request.input.operation == RASP_SK_CREATE && request.result.effect == RASP_SK_KEY_CREATED) {
    request.cleanup = true;
  }
}
void Service::retire(std::size_t index) {
  auto& request = std::span{requests_}[index];
  if (!request.used || !request.taken || request.delivery || request.cleanup || request.taking.load()) {
    return;
  }
  if (std::ranges::any_of(jobs_,
                          [index](const auto& job) { return job.used && !job.closing && job.request == index; })) {
    return;
  }
  wipe_object(request.input);
  wipe_object(request.result);
  request.used = false;
}
void Service::drain_releases() {
  const auto observed = delivery_released_.load();
  bool committing = false;
  for (std::size_t index = 0; index < requests_.size(); ++index) {
    auto& request = std::span{requests_}[index];
    const auto allocation = request.delivery_ordinal.load(std::memory_order_acquire);
    committing = committing || (request.delivery && allocation == kDeliveryCommitting);
    if (request.delivery && allocation == 0) {
      request.delivery = false;
      retire(index);
    }
  }
  if (!committing) {
    delivery_drained_.store(observed);
  }
}
std::uint32_t Service::load() {
  auto const scratch = job_bytes(std::span{jobs_}[0]);
  bool exists = false;
  std::uint32_t written = 0;
  std::uint32_t status = platform_->open_storage(application_, scratch, written, exists);
  if (status != RASP_SK_OP_OK) {
    return status;
  }
  storage_owned_ = true;
  if (!platform_->random(entropy_)) {
    return RASP_SK_OP_INTERNAL_ERROR;
  }
  std::array<std::uint8_t, 32> app_hash{};
  status = profiles(app_hash);
  if (status != RASP_SK_OP_OK) {
    return status;
  }
  if (exists) {
    if (written != kManifestBytes) {
      return RASP_SK_OP_STORAGE_CORRUPT;
    }
    if (!decode_manifest(scratch, manifest_) || manifest_.application_sha256 != app_hash) {
      return RASP_SK_OP_STORAGE_CORRUPT;
    }
    if (!valid_loaded()) {
      return RASP_SK_OP_STORAGE_CORRUPT;
    }
  } else {
    std::memset(&manifest_, 0, sizeof(manifest_));
    manifest_.application_sha256 = app_hash;
    bool generated = false;
    for (std::size_t attempt = 0; attempt < 4 && !generated; ++attempt) {
      if (!platform_->random(manifest_.generation.bytes)) {
        return RASP_SK_OP_INTERNAL_ERROR;
      }
      generated = nonzero(manifest_.generation);
    }
    if (!generated || !encode_manifest(manifest_, scratch)) {
      return RASP_SK_OP_INTERNAL_ERROR;
    }
    PlatformDiagnostic diagnostic;
    status = platform_->persist(scratch, diagnostic);
    if (!valid_diagnostic(diagnostic)) {
      status = RASP_SK_OP_PLATFORM_ERROR;
    }
    if (status != RASP_SK_OP_OK) {
      return RASP_SK_OP_STORAGE_UNAVAILABLE;
    }
  }
  return recover(scratch);
}
std::uint32_t Service::profiles(std::span<std::uint8_t, 32> app_hash) {
  if (application_.length == 0 || application_.length > 256 ||
      !utf8(std::span(application_.name).first(application_.length))) {
    return RASP_SK_OP_PLATFORM_ERROR;
  }
  std::array<std::uint8_t, 384> application_bytes{};
  const auto append_length = [&](std::size_t offset, std::uint32_t length) {
    for (std::size_t byte = 0; byte < 4; ++byte) {
      std::span{application_bytes}[offset + byte] = static_cast<std::uint8_t>(length >> ((3 - byte) * 8));
    }
  };
  append_length(0, application_.length);
  std::ranges::copy(std::span(application_.name).first(application_.length),
                    std::span(application_bytes).subspan(4).begin());
  append_length(4 + application_.length, config_.signing_scope_length);
  std::ranges::copy(std::span(config_.signing_scope).first(config_.signing_scope_length),
                    std::span(application_bytes).subspan(8 + application_.length).begin());
  if (!digest(std::span(application_bytes).first(8 + application_.length + config_.signing_scope_length), app_hash)) {
    return RASP_SK_OP_INTERNAL_ERROR;
  }
  for (std::size_t index = 0; index < config_.namespace_count; ++index) {
    auto const profile_scratch = job_bytes(std::span{jobs_}[1]);
    const auto length = profile_bytes(application_, config_, std::span(config_.namespaces)[index], profile_scratch);
    if (length == 0 || !digest(std::span(profile_scratch).first(length), std::span{namespaces_}[index].profile)) {
      return RASP_SK_OP_INTERNAL_ERROR;
    }
  }
  return RASP_SK_OP_OK;
}
bool Service::valid_loaded() const {
  std::array<std::uint32_t, 4> counts{};
  for (const auto& record : manifest_.records) {
    if (record.state == KeyState::kEmpty) {
      continue;
    }
    const auto space = std::ranges::find(std::span(config_.namespaces).first(config_.namespace_count),
                                         record.info.namespace_selector, &RaspScopedKeyNamespaceSpecV1::selector);
    if (space == std::span(config_.namespaces).first(config_.namespace_count).end()) {
      return false;
    }
    const auto index =
        static_cast<std::size_t>(space - std::span(config_.namespaces).first(config_.namespace_count).begin());
    if (++std::span(counts)[index] > 8) {
      return false;
    }
    if (!valid_binding(record.info, *space) ||
        !std::ranges::equal(record.info.profile_sha256, std::span{namespaces_}[index].profile) ||
        (record.state == KeyState::kLive && !valid_info(record.info, *space)) ||
        (std::ranges::any_of(record.info.public_key_x963, [](auto byte) { return byte != 0; }) &&
         !valid_point(record.info.public_key_x963))) {
      return false;
    }
  }
  return true;
}
std::uint32_t Service::recover(std::span<std::uint8_t> scratch) {
  candidate_ = manifest_;
  bool changed = false;
  for (std::size_t index = 0; index < manifest_.records.size(); ++index) {
    const auto& record = std::span{manifest_.records}[index];
    if (record.state == KeyState::kReserved || record.state == KeyState::kDeletePending) {
      const auto space = std::ranges::find(std::span(config_.namespaces).first(config_.namespace_count),
                                           record.info.namespace_selector, &RaspScopedKeyNamespaceSpecV1::selector);
      reference(
          std::span{jobs_}[0], record.info.key_id,
          static_cast<std::uint32_t>(space - std::span(config_.namespaces).first(config_.namespace_count).begin()));
      PlatformDiagnostic diagnostic;
      if (platform_->erase(std::span{jobs_}[0].reference, cleanup_proof(record.info), diagnostic) == RASP_SK_OP_OK &&
          valid_diagnostic(diagnostic)) {
        std::span{candidate_.records}[index] = {};
        changed = true;
      }
    }
  }
  if (changed) {
    PlatformDiagnostic diagnostic;
    if (!encode_manifest(candidate_, scratch) || platform_->persist(scratch, diagnostic) != RASP_SK_OP_OK ||
        !valid_diagnostic(diagnostic)) {
      storage_fault_ = true;
      return RASP_SK_OP_STORAGE_UNAVAILABLE;
    }
    manifest_ = candidate_;
  }
  wipe(scratch);
  return RASP_SK_OP_OK;
}
std::int32_t Service::open(const RaspScopedKeyClientSpecV1& input, RaspScopedKeyClientOpenedV1& output) {
  if (platform_->main_thread()) {
    return RASP_SK_CALL_WRONG_THREAD;
  }
  Posts posts;
  {
    std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
      return RASP_SK_CALL_BUSY;
    }
    if (state_ == State::kClosing) {
      dispatch(posts);
      lock.unlock();
      post(posts);
      return RASP_SK_CALL_CLOSING;
    }
    if (state_ != State::kIdle && state_ != State::kClosed) {
      return RASP_SK_CALL_BUSY;
    }
    if (!valid_spec(input)) {
      output.operation_status = RASP_SK_OP_INVALID_ARGUMENT;
      return RASP_SK_CALL_OK;
    }
    config_ = input;
    blocked_.fill(false);
    handles_.fill({});
    namespaces_.fill({});
    storage_fault_ = false;
    clock_seen_ = false;
    clock_fault_ = false;
    sampled_valid_.store(false);
    sampled_fault_.store(false);
    state_ = State::kOpening;
  }
  std::uint32_t status = load();
  std::uint64_t now = 0;
  if (status == RASP_SK_OP_OK && (!refresh_clock() || !sample(now) || !token(client_))) {
    status = RASP_SK_OP_INTERNAL_ERROR;
  }
  for (std::size_t index = 0; status == RASP_SK_OP_OK && index < config_.namespace_count; ++index) {
    if (!token(std::span{namespaces_}[index].token)) {
      status = RASP_SK_OP_INTERNAL_ERROR;
    }
  }
  if (status != RASP_SK_OP_OK && storage_owned_) {
    storage_owned_ = !platform_->close_storage();
  }
  std::unique_lock lock(mutex_);
  output.operation_status = status;
  if (status != RASP_SK_OP_OK) {
    state_ = storage_owned_ ? State::kClosing : State::kIdle;
    if (storage_owned_) {
      storage_fault_ = true;
      dispatch(posts);
    }
    lock.unlock();
    post(posts);
    return RASP_SK_CALL_OK;
  }
  state_ = State::kReady;
  output.client = client_;
  output.namespace_count = config_.namespace_count;
  for (std::size_t index = 0; index < config_.namespace_count; ++index) {
    auto& entry = std::span(output.namespaces)[index];
    entry.selector = std::span(config_.namespaces)[index].selector;
    entry.namespace_handle = std::span{namespaces_}[index].token;
  }
  return RASP_SK_CALL_OK;
}
void Service::reference(Job& job, const RaspScopedKeyTokenV1& key, std::uint32_t space) {
  const auto record = record_index(key);
  job.reference.key_id = key;
  job.record = static_cast<std::uint32_t>(record);
  job.reference.generation = manifest_.generation;
  job.reference.space = std::span(config_.namespaces)[space];
  std::ranges::copy(std::span{namespaces_}[space].profile, job.reference.profile_sha256.begin());
  if (record < manifest_.records.size()) {
    job.reference.key_id = std::span{manifest_.records}[record].info.key_id;
    job.measured = std::span{manifest_.records}[record].info;
  }
}
void Service::invalidate(const Request& subject, Posts& posts) {
  const auto targets = subject.targets;
  const auto space = subject.space;
  const bool whole = subject.input.operation == RASP_SK_RESET_NAMESPACE;
  for (std::size_t index = 0; index < manifest_.records.size(); ++index) {
    if ((targets & bit(index)) != 0) {
      std::span{blocked_}[index] = true;
      for (auto& handle : handles_) {
        if (same(handle.key_id, std::span{manifest_.records}[index].info.key_id)) {
          handle.used = false;
        }
      }
    }
  }
  for (std::size_t index = 0; index < requests_.size(); ++index) {
    auto& request = std::span{requests_}[index];
    if (!request.used || request.space != space || request.input.operation == RASP_SK_DELETE ||
        request.input.operation == RASP_SK_RESET_NAMESPACE) {
      continue;
    }
    const bool matching =
        std::ranges::any_of(std::span(request.target_ids).first(request.target_count), [&](const auto& key) {
          return std::ranges::any_of(std::span(subject.target_ids).first(subject.target_count),
                                     [&](const auto& target) { return same(key, target); });
        });
    if (whole || matching) {
      fail(request, RASP_SK_OP_INVALIDATED);
      for (const auto& job : jobs_) {
        if (job.used && job.request == index && posts.cancel_count < posts.cancels.size()) {
          std::span{posts.cancels}[posts.cancel_count++] = job.token;
        }
      }
    }
  }
}
std::int32_t Service::submit(const RaspScopedKeySubmitV1& input, RaspScopedKeyAdmissionV1& output) {
  if (!refresh_clock()) {
    return RASP_SK_CALL_BUSY;
  }
  Posts posts;
  {
    const std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
      return RASP_SK_CALL_BUSY;
    }
    drain_releases();
    if (state_ != State::kReady || !same(client_, input.client)) {
      return state_ == State::kClosing ? RASP_SK_CALL_CLOSING : RASP_SK_CALL_NOT_FOUND;
    }
    output.admission_state = RASP_SK_REJECTED;
    output.operation_status = RASP_SK_OP_INVALID_ARGUMENT;
    if (storage_fault_) {
      output.operation_status = RASP_SK_OP_STORAGE_UNAVAILABLE;
      return RASP_SK_CALL_OK;
    }
    const auto space = namespace_index(input.namespace_handle);
    if (!valid_submit(input) || space == 4) {
      output.operation_status = space == 4 ? RASP_SK_OP_WRONG_NAMESPACE : RASP_SK_OP_INVALID_ARGUMENT;
      return RASP_SK_CALL_OK;
    }
    std::uint64_t now = 0;
    if (!sample(now) || now > std::numeric_limits<std::uint64_t>::max() - UINT64_C(300000000000)) {
      output.operation_status = RASP_SK_OP_CLOCK_UNAVAILABLE;
      return RASP_SK_CALL_OK;
    }
    if (input.operation <= RASP_SK_SIGN && pending(static_cast<std::uint32_t>(space))) {
      output.operation_status = RASP_SK_OP_CLEANUP_PENDING;
      return RASP_SK_CALL_OK;
    }
    std::size_t record = 32;
    auto status = resolve(input, now, record);
    if (status != RASP_SK_OP_OK) {
      output.operation_status = status;
      return RASP_SK_CALL_OK;
    }
    auto* available = std::ranges::find(requests_, false, &Request::used);
    if (available == requests_.end()) {
      output.operation_status = RASP_SK_OP_RESOURCE_EXHAUSTED;
      return RASP_SK_CALL_OK;
    }
    std::size_t handle_slot = 16;
    status = capacity(input, space, handle_slot);
    if (status != RASP_SK_OP_OK) {
      output.operation_status = status;
      return RASP_SK_CALL_OK;
    }
    RaspScopedKeyTokenV1 request_token{};
    if (!token(request_token)) {
      output.operation_status = RASP_SK_OP_INTERNAL_ERROR;
      return RASP_SK_CALL_OK;
    }
    available->input = input;
    available->space = static_cast<std::uint32_t>(space);
    if (!targets(*available, record, posts)) {
      output.operation_status = RASP_SK_OP_STORAGE_CORRUPT;
      return RASP_SK_CALL_OK;
    }
    if (input.operation >= RASP_SK_DELETE) {
      output.durability = RASP_SK_IN_MEMORY_ONLY;
    }
    available->input = input;
    available->token = request_token;
    available->used = true;
    available->taken = false;
    available->delivery = false;
    available->cleanup = false;
    available->terminal = false;
    available->final_status = RASP_SK_OP_OK;
    available->space = static_cast<std::uint32_t>(space);
    available->handle_slot = static_cast<std::uint32_t>(handle_slot);
    available->deadline = now + (static_cast<std::uint64_t>(input.request_ttl_ms) * UINT64_C(1000000));
    result_header(*available);
    if (handle_slot < 16) {
      std::span{handles_}[handle_slot] = {};
      std::span{handles_}[handle_slot].used = true;
      std::span{handles_}[handle_slot].token = {};
      std::span{handles_}[handle_slot].owner = request_token;
    }
    output.request = request_token;
    output.admission_state = RASP_SK_ACCEPTED;
    output.operation_status = RASP_SK_OP_OK;
    dispatch(posts);
  }
  post(posts);
  return RASP_SK_CALL_OK;
}
std::uint32_t Service::resolve(const RaspScopedKeySubmitV1& input, std::uint64_t now, std::size_t& record) const {
  const auto space = namespace_index(input.namespace_handle);
  if (input.operation == RASP_SK_REOPEN || input.operation == RASP_SK_DELETE) {
    record = record_index(input.input.key_id);
  } else if (input.operation == RASP_SK_SIGN || input.operation == RASP_SK_DESCRIBE) {
    const auto handle = handle_index(input.input.key_handle);
    if (handle == 16 || now >= std::span{handles_}[handle].expires) {
      return handle == 16 ? RASP_SK_OP_STALE_HANDLE : RASP_SK_OP_EXPIRED;
    }
    record = record_index(std::span{handles_}[handle].key_id);
  }
  if (input.operation != RASP_SK_CREATE && input.operation != RASP_SK_RESET_NAMESPACE &&
      (record == 32 ||
       std::span{manifest_.records}[record].info.namespace_selector != std::span(config_.namespaces)[space].selector)) {
    return record == 32 ? RASP_SK_OP_NOT_FOUND : RASP_SK_OP_WRONG_NAMESPACE;
  }
  if (input.operation == RASP_SK_SIGN &&
      !std::ranges::equal(input.input.sign.expected_purpose, std::span(config_.namespaces)[space].purpose)) {
    return RASP_SK_OP_WRONG_PURPOSE;
  }
  return RASP_SK_OP_OK;
}
std::uint32_t Service::capacity(const RaspScopedKeySubmitV1& input, std::size_t space, std::size_t& handle_slot) const {
  if (input.operation == RASP_SK_CREATE || input.operation == RASP_SK_REOPEN) {
    const auto* const slot = std::ranges::find(handles_, false, &Handle::used);
    if (slot == handles_.end()) {
      return RASP_SK_OP_RESOURCE_EXHAUSTED;
    }
    handle_slot = static_cast<std::size_t>(slot - handles_.begin());
  }
  if (input.operation == RASP_SK_CREATE) {
    std::size_t count = 0;
    for (const auto& entry : manifest_.records) {
      count += entry.state != KeyState::kEmpty &&
                       entry.info.namespace_selector == std::span(config_.namespaces)[space].selector
                   ? 1U
                   : 0U;
    }
    for (const auto& request : requests_) {
      count += request.used && !request.terminal && request.input.operation == RASP_SK_CREATE && request.space == space
                   ? 1U
                   : 0U;
    }
    if (count >= 8) {
      return RASP_SK_OP_RESOURCE_EXHAUSTED;
    }
  }
  return RASP_SK_OP_OK;
}
bool Service::targets(Request& request, std::size_t record, Posts& posts) {
  request.target_ids.fill({});
  request.target_count = 0;
  if (request.input.operation == RASP_SK_DELETE || request.input.operation == RASP_SK_RESET_NAMESPACE) {
    std::uint32_t targets = 0;
    for (std::size_t index = 0; index < manifest_.records.size(); ++index) {
      if ((request.input.operation == RASP_SK_DELETE && index == record) ||
          (request.input.operation == RASP_SK_RESET_NAMESPACE &&
           std::span{manifest_.records}[index].state != KeyState::kEmpty &&
           std::span{manifest_.records}[index].info.namespace_selector ==
               std::span(config_.namespaces)[request.space].selector)) {
        if (request.target_count == 8) {
          return false;
        }
        targets |= bit(index);
        std::span{request.target_ids}[request.target_count++] = std::span{manifest_.records}[index].info.key_id;
      }
    }
    request.targets = targets;
    invalidate(request, posts);
    if (request.input.operation == RASP_SK_RESET_NAMESPACE) {
      std::span{namespaces_}[request.space].resetting = true;
    }
  } else {
    request.targets = record < 32 ? bit(record) : 0;
    if (record < 32) {
      request.target_ids[0] = std::span{manifest_.records}[record].info.key_id;
      request.target_count = 1;
    }
  }
  return true;
}
void Service::gate_input(std::uint32_t space_index, RaspLocalGateRequestV1& input) const {
  const auto& space = std::span(config_.namespaces)[space_index];
  input = {};
  input.abi_version = 1;
  input.struct_size = sizeof(input);
  std::memcpy(std::span(input.operation).data(), std::span(space.gate_operation).data(), space.gate_operation_length);
  constexpr std::string_view kHex = "0123456789abcdef";
  for (std::size_t index = 0; index < 32; ++index) {
    std::span(input.expected_policy_sha256)[index * 2] = kHex[std::span(space.expected_policy_sha256)[index] >> 4U];
    std::span(input.expected_policy_sha256)[(index * 2) + 1] =
        kHex[std::span(space.expected_policy_sha256)[index] & 15U];
  }
}
bool Service::gate(const Request& request, RaspLocalGateResultV1& output) const {
  RaspLocalGateRequestV1 input{};
  gate_input(request.space, input);
  const auto status = rasp_local_policy_gate_v1(&input, sizeof(input), &output, sizeof(output));
  return gate_allowed(status, output, std::span(config_.namespaces)[request.space].gate_mode);
}
bool Service::matches_prompt(const Job& job, const PromptSnapshot& snapshot) const {
  if (!job.used || job.closing || !same(job.token, snapshot.job) || job.request >= requests_.size()) {
    return false;
  }
  const auto& request = std::span(requests_)[job.request];
  if (!request.used || request.space >= config_.namespace_count) {
    return false;
  }
  RaspLocalGateRequestV1 input{};
  gate_input(request.space, input);
  return std::memcmp(&input, &snapshot.gate_request, sizeof(input)) == 0 &&
         snapshot.gate_mode == std::span(config_.namespaces)[request.space].gate_mode &&
         same(request.token, snapshot.request) && same(client_, snapshot.client) &&
         same(request.input.client, snapshot.client) && same(manifest_.generation, snapshot.generation) &&
         same(job.reference.generation, snapshot.generation) && same(job.reference.key_id, snapshot.key) &&
         same(request.input.input.sign.key, snapshot.handle) &&
         same(std::span(namespaces_)[request.space].token, snapshot.namespace_handle) &&
         job.reference.profile_sha256 == snapshot.profile &&
         std::span(namespaces_)[request.space].profile == snapshot.profile;
}
std::uint32_t Service::prompt_status(const Job& job, std::uint64_t now) const {
  if (!job.used || job.closing || !job.prompt || !job.auth_pending || job.authenticated ||
      job.request >= requests_.size()) {
    return RASP_SK_OP_NOT_FOUND;
  }
  const auto& request = std::span(requests_)[job.request];
  if (!request.used || request.input.operation != RASP_SK_SIGN || request.space >= config_.namespace_count ||
      !same(request.input.client, client_)) {
    return RASP_SK_OP_NOT_FOUND;
  }
  const auto status = eligible(request, now);
  if (status != RASP_SK_OP_OK) {
    return status;
  }
  const auto record = record_index(job.reference.key_id);
  const auto handle = handle_index(request.input.input.sign.key);
  if (request.taken || request.terminal || record >= manifest_.records.size() || handle >= handles_.size() ||
      !same(manifest_.generation, job.reference.generation) ||
      std::span(manifest_.records)[record].state != KeyState::kLive || std::span(blocked_)[record] ||
      !same(std::span(handles_)[handle].key_id, job.reference.key_id) ||
      std::span(namespaces_)[request.space].profile != job.reference.profile_sha256 ||
      !std::ranges::equal(std::span(manifest_.records)[record].info.profile_sha256, job.reference.profile_sha256)) {
    return RASP_SK_OP_INVALIDATED;
  }
  return RASP_SK_OP_OK;
}
std::uint32_t Service::prompt_eligibility(const RaspScopedKeyTokenV1& value, PromptCheck& check) {
  check.operation_status = RASP_SK_OP_BUSY;
  if (!refresh_clock()) {
    return check.operation_status;
  }
  {
    const std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
      return check.operation_status;
    }
    const auto* job =
        std::ranges::find_if(jobs_, [&](const auto& item) { return item.used && same(item.token, value); });
    std::uint64_t now = 0;
    if (job == jobs_.end()) {
      check.operation_status = RASP_SK_OP_NOT_FOUND;
    } else {
      check.operation_status = sample(now) ? prompt_status(*job, now) : RASP_SK_OP_CLOCK_UNAVAILABLE;
    }
    if (check.operation_status != RASP_SK_OP_OK) {
      return check.operation_status;
    }
    const auto& request = std::span(requests_)[job->request];
    auto& snapshot = check.snapshot;
    snapshot.job = job->token;
    snapshot.request = request.token;
    snapshot.client = client_;
    snapshot.generation = job->reference.generation;
    snapshot.key = job->reference.key_id;
    snapshot.handle = request.input.input.sign.key;
    snapshot.namespace_handle = std::span(namespaces_)[request.space].token;
    snapshot.profile = job->reference.profile_sha256;
    snapshot.gate_mode = std::span(config_.namespaces)[request.space].gate_mode;
    gate_input(request.space, snapshot.gate_request);
  }
  check.gate_call_status = rasp_local_policy_gate_v1(&check.snapshot.gate_request, sizeof(check.snapshot.gate_request),
                                                     &check.gate, sizeof(check.gate));
  check.gate_present = 1;
  const bool refreshed = refresh_clock();
  check.operation_status = RASP_SK_OP_BUSY;
  const std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    return check.operation_status;
  }
  const auto* job = std::ranges::find_if(jobs_, [&](const auto& item) { return item.used && same(item.token, value); });
  if (job == jobs_.end() || !job->auth_pending || !matches_prompt(*job, check.snapshot)) {
    check.operation_status = RASP_SK_OP_NOT_FOUND;
    return check.operation_status;
  }
  auto& request = std::span(requests_)[job->request];
  if (!request.taken) {
    request.result.gate = check.gate;
    request.result.gate_present = 1;
    check.gate_committed = 1;
  }
  std::uint64_t now = 0;
  if (refreshed) {
    check.operation_status = sample(now) ? prompt_status(*job, now) : RASP_SK_OP_CLOCK_UNAVAILABLE;
  }
  if (check.operation_status == RASP_SK_OP_OK &&
      !gate_allowed(check.gate_call_status, check.gate, check.snapshot.gate_mode)) {
    check.operation_status = RASP_SK_OP_GATE_REJECTED;
  }
  return check.operation_status;
}
std::uint32_t prompt_eligibility(const RaspScopedKeyTokenV1& job, PromptCheck& check) {
  EntryLease const entry;
  check = {};
  Service* owner = entry.get();
  if (owner == nullptr) {
    check.operation_status = entry.busy() ? RASP_SK_OP_BUSY : RASP_SK_OP_NOT_READY;
    return check.operation_status;
  }
  return owner->prompt_eligibility(job, check);
}
std::uint32_t Service::eligible(const Request& request, std::uint64_t now) const {
  if (storage_fault_) {
    return RASP_SK_OP_STORAGE_UNAVAILABLE;
  }
  if (request.final_status != RASP_SK_OP_OK) {
    return request.final_status;
  }
  if (state_ != State::kReady) {
    return RASP_SK_OP_CANCELLED;
  }
  if (now >= request.deadline) {
    return RASP_SK_OP_EXPIRED;
  }
  if (request.input.operation == RASP_SK_SIGN || request.input.operation == RASP_SK_DESCRIBE) {
    const auto found = handle_index(request.input.input.key_handle);
    if (found == 16) {
      return RASP_SK_OP_STALE_HANDLE;
    }
    if (now >= std::span{handles_}[found].expires) {
      return RASP_SK_OP_EXPIRED;
    }
  }
  return RASP_SK_OP_OK;
}
template <typename Output>
void Service::snapshot_retained(Output& output) const {
  output.retained_requests = static_cast<std::uint32_t>(std::ranges::count(requests_, true, &Request::used));
  output.retained_jobs = static_cast<std::uint32_t>(std::ranges::count(jobs_, true, &Job::used));
}
std::int32_t Service::take(const RaspScopedKeyTakeRequestV1& input, RaspScopedKeyTakeResultV1& output) {
  if (!refresh_clock()) {
    return RASP_SK_CALL_BUSY;
  }
  Posts posts;
  std::unique_lock lock(mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    return RASP_SK_CALL_BUSY;
  }
  if (!same(client_, input.client) || (state_ != State::kReady && state_ != State::kClosing)) {
    return RASP_SK_CALL_NOT_FOUND;
  }
  auto* const found = std::ranges::find_if(
      requests_, [&](const auto& request) { return request.used && same(request.token, input.request); });
  output.request = input.request;
  if (found == requests_.end() || found->taken) {
    output.take_state = RASP_SK_UNKNOWN_REQUEST;
    snapshot_retained(output);
    return RASP_SK_CALL_OK;
  }
  std::uint64_t now = 0;
  if (!sample(now)) {
    fail(*found, RASP_SK_OP_CLOCK_UNAVAILABLE);
  } else if (now >= found->deadline && found->final_status == RASP_SK_OP_OK) {
    fail(*found, RASP_SK_OP_EXPIRED);
  }
  output.durability = found->result.durability;
  if (!found->terminal) {
    output.take_state = RASP_SK_PENDING;
    snapshot_retained(output);
    return RASP_SK_CALL_OK;
  }
  if (found->taking.exchange(true)) {
    return RASP_SK_CALL_BUSY;
  }
  native_borrowers_.fetch_add(1);
  const auto index = static_cast<std::size_t>(found - requests_.begin());
  output.completion = found->result;
  const bool check_gate = found->result.operation_status == RASP_SK_OP_OK && found->input.operation == RASP_SK_SIGN;
  lock.unlock();
  const bool allowed = !check_gate || gate(*found, output.completion.gate);
  if (!refresh_clock() || !lock.try_lock()) {
    output = {};
    output.abi_version = 1;
    output.struct_size = sizeof(output);
    found->taking.store(false);
    native_borrowers_.fetch_sub(1);
    return RASP_SK_CALL_BUSY;
  }
  if (check_gate) {
    found->result.gate = output.completion.gate;
    found->result.gate_present = 1;
  }
  std::uint32_t status = RASP_SK_OP_CLOCK_UNAVAILABLE;
  if (sample(now)) {
    status = eligible(*found, now);
  }
  if (!allowed && status == RASP_SK_OP_OK) {
    status = RASP_SK_OP_GATE_REJECTED;
  }
  if (status != RASP_SK_OP_OK) {
    fail(*found, status);
  }
  output.completion = found->result;
  output.take_state = RASP_SK_COMPLETED;
  output.durability = found->result.durability;
  found->taken = true;
  found->taking.store(false);
  native_borrowers_.fetch_sub(1);
  retire(index);
  dispatch(posts);
  snapshot_retained(output);
  lock.unlock();
  post(posts);
  return RASP_SK_CALL_OK;
}
std::int32_t Service::control(const RaspScopedKeyControlV1& input, RaspScopedKeyControlResultV1& output) {
  Posts posts;
  {
    const std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
      return RASP_SK_CALL_BUSY;
    }
    if (state_ == State::kClosed && same(last_closed_, input.client) && input.action == RASP_SK_CLOSE_CLIENT) {
      output.outcome = RASP_SK_ALREADY_CLOSED;
      output.operation_status = RASP_SK_OP_OK;
      return RASP_SK_CALL_OK;
    }
    if (!same(client_, input.client) || (state_ != State::kReady && state_ != State::kClosing)) {
      return RASP_SK_CALL_NOT_FOUND;
    }
    output.client = client_;
    output.operation_status = RASP_SK_OP_OK;
    output.outcome = RASP_SK_APPLIED;
    apply_control(input, output);
    for (const auto& job : jobs_) {
      if (job.used && !job.closing && std::span{requests_}[job.request].final_status != RASP_SK_OP_OK) {
        std::span{posts.cancels}[posts.cancel_count++] = job.token;
      }
    }
    for (std::size_t index = 0; index < requests_.size(); ++index) {
      retire(index);
    }
    dispatch(posts);
    snapshot_retained(output);
    output.retained_callbacks = static_cast<std::uint32_t>(std::ranges::count(requests_, true, &Request::delivery));
  }
  post(posts);
  return RASP_SK_CALL_OK;
}
void Service::apply_control(const RaspScopedKeyControlV1& input, RaspScopedKeyControlResultV1& output) {
  if (input.action == RASP_SK_CANCEL) {
    auto* found = std::ranges::find_if(
        requests_, [&](const auto& request) { return request.used && same(request.token, input.target); });
    if (found == requests_.end() || found->taken) {
      output.outcome = found == requests_.end() ? RASP_SK_CONTROL_NOT_FOUND : RASP_SK_TOO_LATE;
      return;
    }
    fail(*found, RASP_SK_OP_CANCELLED);
  } else if (input.action == RASP_SK_RELEASE_KEY) {
    const auto found = handle_index(input.target);
    if (found == 16) {
      output.outcome = RASP_SK_CONTROL_NOT_FOUND;
      return;
    }
    {
      std::span{handles_}[found].used = false;
      for (auto& request : requests_) {
        if (request.used && request.input.operation == RASP_SK_SIGN &&
            same(request.input.input.sign.key, input.target)) {
          fail(request, RASP_SK_OP_CANCELLED);
        }
      }
    }
  } else {
    state_ = State::kClosing;
    handles_.fill({});
    for (auto& request : requests_) {
      if (request.used) {
        fail(request, RASP_SK_OP_CANCELLED);
        request.taken = true;
      }
    }
    output.outcome = RASP_SK_DRAINING;
  }
}
bool Service::acknowledge_delivery(const RaspScopedKeyTokenV1& value) {
  std::uint64_t prefix = 0;
  std::uint64_t allocation = 0;
  std::memcpy(&prefix, std::span(value.bytes).data(), 8);
  std::memcpy(&allocation, std::span(value.bytes).subspan(8).data(), 8);
  if (allocation <= kDeliveryCommitting) {
    return false;
  }
  for (auto& request : requests_) {
    if (allocation != 0 && request.delivery_ordinal.load(std::memory_order_acquire) == allocation &&
        request.delivery_prefix.load(std::memory_order_relaxed) == prefix) {
      auto expected = allocation;
      if (request.delivery_ordinal.compare_exchange_strong(expected, kDeliveryCommitting, std::memory_order_acq_rel)) {
        delivery_released_.fetch_add(1);
        request.delivery_ordinal.store(0, std::memory_order_release);
        return true;
      }
    }
  }
  return false;
}
bool Service::delivery_pending() const { return delivery_released_.load() != delivery_drained_.load(); }
/// Closing forbids new leases: at most eight commits can need folding; epoch snapshots precede each scan.
void Service::drain_delivery() {
  for (std::size_t attempt = 0; attempt < requests_.size(); ++attempt) {
    Posts posts;
    {
      const std::unique_lock lock(mutex_, std::try_to_lock);
      if (!lock.owns_lock() || !delivery_pending()) {
        return;
      }
      dispatch(posts);
    }
    post(posts);
    if (!delivery_pending()) {
      return;
    }
  }
}
bool Service::reserve_delivery(const RaspScopedKeyTokenV1& value) {
  Posts posts;
  {
    const std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
      return false;
    }
    auto* found = std::ranges::find_if(requests_,
                                       [&](const auto& request) { return request.used && same(request.token, value); });
    if (found == requests_.end() || found->taken || found->delivery || !found->terminal || state_ != State::kReady) {
      return false;
    }
    std::uint64_t prefix = 0;
    std::uint64_t allocation = 0;
    std::memcpy(&prefix, std::span(value.bytes).data(), 8);
    std::memcpy(&allocation, std::span(value.bytes).subspan(8).data(), 8);
    found->delivery = true;
    found->delivery_prefix.store(prefix, std::memory_order_relaxed);
    found->delivery_ordinal.store(allocation, std::memory_order_release);
    dispatch(posts);
  }
  post(posts);
  return true;
}
bool begin_delivery(const RaspScopedKeyTokenV1& request) {
  EntryLease const entry;
  Service* owner = entry.get();
  return owner != nullptr && owner->reserve_delivery(request);
}
void end_delivery(const RaspScopedKeyTokenV1& request) {
  Service* stable = registry().stable.load(std::memory_order_acquire);
  if (stable != nullptr && stable->acknowledge_delivery(request)) {
    drain_delivery_acknowledgments();
  }
}

}  // namespace rasp::keys
