/// Two bounded executor leases; provider work, persistence and UI callbacks stay outside the state lock.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>
#include <variant>

#include "encoding.h"
#include "entry.h"
#include "manifest.h"
#include "rasp/local_policy_host.h"
#include "rasp/scoped_key.h"
#include "service.h"

namespace rasp::keys {
namespace {
/// Fixed in-arena gate storage leaves the full4958-byte message and1024-byte adapter context disjoint.
RaspLocalGateResultV1& job_gate(Job& job) { return std::get_if<SigningScratch>(&job.scratch)->gate; }
/// Context belongs to the adapter until its worker-side release acknowledges no borrowers.
std::span<std::uint8_t> context(Job& job) { return std::get_if<SigningScratch>(&job.scratch)->context; }
/// Only known operation statuses can cross a child boundary as outcomes.
std::uint32_t outcome(std::uint32_t status) {
  return status >= RASP_SK_OP_OK && status <= RASP_SK_OP_INTERNAL_ERROR ? status : RASP_SK_OP_PLATFORM_ERROR;
}
/// Recognize persisted mutation operations without a generic action dispatcher.
bool mutates(const Request& request) {
  return request.cleanup || request.input.operation == RASP_SK_CREATE || request.input.operation == RASP_SK_DELETE ||
         request.input.operation == RASP_SK_RESET_NAMESPACE;
}
/// Reset job metadata in place without a large stack temporary or an early context wipe.
void clear(Job& job) {
  const auto wipe_memory = [](auto& memory) {
    for (volatile auto& byte : std::as_writable_bytes(std::span(&memory, 1))) {
      byte = std::byte{};
    }
  };
  if (auto* memory = std::get_if<0>(&job.scratch); memory != nullptr) {
    wipe_memory(*memory);
  } else if (auto* signing = std::get_if<SigningScratch>(&job.scratch); signing != nullptr) {
    wipe_memory(*signing);
  }
  job.scratch.emplace<0>();
  job.reference = {};
  job.measured = {};
  job.used = false;
  job.running = false;
  job.posted = false;
  job.auth_pending = false;
  job.authenticated = false;
  job.yielded_for_auth = false;
  job.prompt = false;
  job.closing = false;
  job.cleanup = false;
}
}  // namespace
std::span<std::uint8_t, 8192> job_bytes(Job& job) { return *std::get_if<0>(&job.scratch); }
void Service::dispatch(Posts& posts) {
  drain_releases();
  for (auto& job : jobs_) {
    if (posts.count == posts.jobs.size()) {
      return;
    }
    if (job.used) {
      if (!job.posted && !job.running && !job.auth_pending) {
        job.posted = true;
        std::span{posts.jobs}[posts.count++] = job.token;
      }
      continue;
    }
    for (std::size_t index = 0; index < requests_.size(); ++index) {
      auto& request = std::span{requests_}[index];
      if (dispatchable(request, index) && reserve_job(job, request, index, posts)) {
        break;
      }
    }
  }
  if (state_ == State::kClosing && posts.count < posts.jobs.size() && native_borrowers_.load() == 0 &&
      std::ranges::none_of(jobs_, &Job::used) && std::ranges::none_of(requests_, &Request::delivery) &&
      std::ranges::none_of(requests_, &Request::cleanup)) {
    auto& job = std::span{jobs_}[0];
    if (token(job.token)) {
      job.scratch.emplace<0>();
      job.used = true;
      job.posted = true;
      job.closing = true;
      std::span{posts.jobs}[posts.count++] = job.token;
    }
  }
}
bool Service::needs_prompt(const Request& request) const {
  return request.input.operation == RASP_SK_SIGN &&
         std::span(config_.namespaces)[request.space].auth_requirement == RASP_SK_CURRENT_BIOMETRY_EACH_REQUEST &&
         request.input.input.sign.interaction == RASP_SK_ALLOW_SYSTEM_BIOMETRY;
}
bool Service::dispatchable(const Request& request, std::size_t index) const {
  if (!request.used || (request.terminal && !request.cleanup) || (state_ != State::kReady && !request.cleanup) ||
      std::ranges::any_of(
          jobs_, [index](const auto& active) { return active.used && !active.closing && active.request == index; })) {
    return false;
  }
  if (mutates(request) && mutation_) {
    return false;
  }
  if (needs_prompt(request) && prompt_) {
    return false;
  }
  const bool conflict = std::ranges::any_of(jobs_, [&](const auto& active) {
    if (!active.used || active.closing) {
      return false;
    }
    const auto& other = std::span{requests_}[active.request];
    return (request.targets & other.targets) != 0 ||
           (request.space == other.space &&
            (request.input.operation == RASP_SK_RESET_NAMESPACE || other.input.operation == RASP_SK_RESET_NAMESPACE));
  });
  return !conflict;
}
bool Service::reserve_job(Job& job, Request& request, std::size_t index, Posts& posts) {
  if (!token(job.token)) {
    fail(request, RASP_SK_OP_INTERNAL_ERROR);
    return false;
  }
  job.scratch.emplace<0>();
  if (request.input.operation == RASP_SK_SIGN) {
    job.scratch.emplace<SigningScratch>();
  }
  job.used = true;
  job.posted = true;
  job.request = static_cast<std::uint32_t>(index);
  job.cleanup = request.cleanup;
  job.prompt = needs_prompt(request);
  mutation_ = mutation_ || mutates(request);
  prompt_ = prompt_ || job.prompt;
  const RaspScopedKeyTokenV1 key = request.target_count == 0 ? RaspScopedKeyTokenV1{} : request.target_ids[0];
  reference(job, key, request.space);
  std::span{posts.jobs}[posts.count++] = job.token;
  return true;
}
void Service::post(const Posts& posts) {
  for (std::size_t index = 0; index < posts.cancel_count; ++index) {
    platform_->cancel(std::span{posts.cancels}[index]);
  }
  for (std::size_t index = 0; index < posts.count; ++index) {
    if (platform_->schedule(std::span{posts.jobs}[index])) {
      continue;
    }
    const std::scoped_lock lock(mutex_);
    auto* const found = std::ranges::find_if(
        jobs_, [&](const auto& job) { return job.used && same(job.token, std::span{posts.jobs}[index]); });
    if (found != jobs_.end() && !found->running) {
      if (!found->closing) {
        auto& request = std::span{requests_}[found->request];
        fail(request, RASP_SK_OP_PLATFORM_ERROR);
        mutation_ = mutation_ && !mutates(request);
        if (found->prompt) {
          prompt_ = false;
        }
      }
      clear(*found);
    }
  }
}
void Service::progress(Job& job, RaspScopedKeyDurabilityV1 durability, RaspScopedKeyEffectV1 effect) {
  const std::scoped_lock lock(mutex_);
  auto& request = std::span{requests_}[job.request];
  request.result.durability = durability;
  request.result.effect = effect;
}
std::uint32_t Service::persist(Job& job) {
  {
    const std::scoped_lock lock(mutex_);
    if (storage_fault_) {
      return RASP_SK_OP_STORAGE_UNAVAILABLE;
    }
  }
  if (!encode_manifest(candidate_, job_bytes(job).first(kManifestBytes))) {
    progress(job, RASP_SK_DURABILITY_UNKNOWN, RASP_SK_EFFECT_UNKNOWN);
    return RASP_SK_OP_INTERNAL_ERROR;
  }
  const auto status = outcome(platform_->persist(job_bytes(job).first(kManifestBytes)));
  if (status != RASP_SK_OP_OK) {
    progress(job, RASP_SK_DURABILITY_UNKNOWN, RASP_SK_EFFECT_UNKNOWN);
    const std::scoped_lock lock(mutex_);
    storage_fault_ = true;
    return RASP_SK_OP_STORAGE_UNAVAILABLE;
  }
  const std::scoped_lock lock(mutex_);
  manifest_ = candidate_;
  return RASP_SK_OP_OK;
}
bool Service::handle(Request& request, const RaspScopedKeyInfoV1& info, std::uint64_t now) {
  if (request.handle_slot >= handles_.size() ||
      now > std::numeric_limits<std::uint64_t>::max() - UINT64_C(300000000000)) {
    return false;
  }
  auto& handle = std::span{handles_}[request.handle_slot];
  if (!handle.used || !same(handle.owner, request.token) || !token(handle.token)) {
    return false;
  }
  handle.key_id = info.key_id;
  handle.expires = now + UINT64_C(300000000000);
  request.result.value_tag = RASP_SK_VALUE_KEY;
  request.result.value.key.key_handle = handle.token;
  request.result.value.key.info = info;
  return true;
}
std::uint32_t Service::cleanup_created(Job& job) {
  const auto absent = outcome(platform_->erase(job.reference));
  if (absent != RASP_SK_OP_OK) {
    return RASP_SK_OP_CLEANUP_PENDING;
  }
  {
    const std::scoped_lock lock(mutex_);
    candidate_ = manifest_;
    std::span{candidate_.records}[job.record] = {};
  }
  const auto saved = persist(job);
  if (saved == RASP_SK_OP_OK) {
    progress(job, RASP_SK_DELETION_CONFIRMED, RASP_SK_KEY_ABSENT);
    const std::scoped_lock lock(mutex_);
    std::span{blocked_}[job.record] = false;
  }
  return saved == RASP_SK_OP_OK ? RASP_SK_OP_OK : RASP_SK_OP_CLEANUP_PENDING;
}
std::uint32_t Service::fresh_key_id(RaspScopedKeyTokenV1& output) {
  for (std::size_t attempt = 0; attempt < 4; ++attempt) {
    if (!platform_->random(output.bytes)) {
      return RASP_SK_OP_INTERNAL_ERROR;
    }
    const std::scoped_lock lock(mutex_);
    if (nonzero(output) && record_index(output) == 32) {
      return RASP_SK_OP_OK;
    }
  }
  return RASP_SK_OP_INTERNAL_ERROR;
}
std::uint32_t Service::create(Job& job) {
  auto& request = std::span{requests_}[job.request];
  const auto allocated = fresh_key_id(job.reference.key_id);
  if (allocated != RASP_SK_OP_OK) {
    return allocated;
  }
  {
    const std::scoped_lock lock(mutex_);
    const auto* const empty = std::ranges::find(manifest_.records, KeyState::kEmpty, &Record::state);
    if (empty == manifest_.records.end()) {
      return RASP_SK_OP_RESOURCE_EXHAUSTED;
    }
    job.record = static_cast<std::uint32_t>(empty - manifest_.records.begin());
    request.targets = UINT32_C(1) << job.record;
    request.target_ids[0] = job.reference.key_id;
    request.target_count = 1;
    candidate_ = manifest_;
    auto& record = std::span{candidate_.records}[job.record];
    record.state = KeyState::kReserved;
    auto& info = record.info;
    info.key_id = job.reference.key_id;
    info.algorithm = RASP_SK_P256_SHA256_MESSAGE_DER;
    info.namespace_selector = job.reference.space.selector;
    info.backend_requirement = job.reference.space.backend_requirement;
    info.auth_requirement = job.reference.space.auth_requirement;
    info.lock_requirement = job.reference.space.lock_requirement;
    info.purpose_length = job.reference.space.purpose_length;
    std::ranges::copy(job.reference.space.purpose, std::span(info.purpose).begin());
    std::ranges::copy(job.reference.profile_sha256, std::span(info.profile_sha256).begin());
    job.measured = info;
  }
  auto status = persist(job);
  if (status != RASP_SK_OP_OK) {
    return status;
  }
  progress(job, RASP_SK_RESERVATION_DURABLE, RASP_SK_EFFECT_UNKNOWN);
  if (!refresh_clock()) {
    return cleanup_created(job) == RASP_SK_OP_OK ? RASP_SK_OP_BUSY : RASP_SK_OP_CLEANUP_PENDING;
  }
  {
    const std::scoped_lock lock(mutex_);
    std::uint64_t now = 0;
    status = sample(now) ? eligible(request, now) : RASP_SK_OP_CLOCK_UNAVAILABLE;
  }
  if (status == RASP_SK_OP_OK) {
    status = outcome(platform_->create(job.reference, job.measured));
    if (status == RASP_SK_OP_OK &&
        (!valid_info(job.measured, job.reference.space) || !same(job.measured.key_id, job.reference.key_id) ||
         !std::ranges::equal(job.measured.profile_sha256, job.reference.profile_sha256))) {
      status = RASP_SK_OP_PLATFORM_ERROR;
    }
  }
  const bool refreshed = refresh_clock();
  {
    const std::scoped_lock lock(mutex_);
    std::uint64_t now = 0;
    if (!refreshed || !sample(now)) {
      status = RASP_SK_OP_CLOCK_UNAVAILABLE;
    } else if (eligible(request, now) != RASP_SK_OP_OK) {
      status = eligible(request, now);
    }
    candidate_ = manifest_;
    if (status == RASP_SK_OP_OK) {
      std::span{candidate_.records}[job.record].state = KeyState::kLive;
      std::span{candidate_.records}[job.record].info = job.measured;
    }
  }
  if (status == RASP_SK_OP_OK) {
    status = persist(job);
    if (status == RASP_SK_OP_OK) {
      progress(job, RASP_SK_LIVE_RECORD_DURABLE, RASP_SK_KEY_CREATED);
      return RASP_SK_OP_OK;
    }
  }
  const auto cleaned = cleanup_created(job);
  return cleaned == RASP_SK_OP_OK ? status : cleaned;
}
std::uint32_t Service::describe(Job& job) {
  const auto status = outcome(platform_->describe(job.reference, job.measured));
  if (status != RASP_SK_OP_OK) {
    return status;
  }
  const std::scoped_lock lock(mutex_);
  const auto& record = std::span{manifest_.records}[job.record];
  return valid_info(job.measured, job.reference.space) && same(record.info.key_id, job.measured.key_id) &&
                 std::ranges::equal(job.measured.profile_sha256, job.reference.profile_sha256) &&
                 std::ranges::equal(job.measured.public_key_x963, record.info.public_key_x963)
             ? RASP_SK_OP_OK
             : RASP_SK_OP_PLATFORM_ERROR;
}
std::uint32_t Service::sign(Job& job) {
  auto& request = std::span{requests_}[job.request];
  if (!job.authenticated) {
    const auto status = describe(job);
    if (status != RASP_SK_OP_OK) {
      return status;
    }
    if (job.reference.space.auth_requirement == RASP_SK_CURRENT_BIOMETRY_EACH_REQUEST) {
      if (request.input.input.sign.interaction == RASP_SK_FORBID) {
        return RASP_SK_OP_AUTH_REQUIRED;
      }
      auto& decision = job_gate(job);
      const bool allowed = gate(request, decision);
      {
        const std::scoped_lock lock(mutex_);
        request.result.gate = decision;
        request.result.gate_present = 1;
        if (!allowed) {
          return RASP_SK_OP_GATE_REJECTED;
        }
        job.auth_pending = true;
      }
      const auto auth = outcome(platform_->authenticate(job.token, job.reference, context(job)));
      if (auth != RASP_SK_OP_OK) {
        const std::scoped_lock lock(mutex_);
        job.auth_pending = false;
        return auth;
      }
      {
        const std::scoped_lock lock(mutex_);
        job.yielded_for_auth = true;
      }
      return RASP_SK_OP_NOT_READY;
    }
  }
  const auto length = message_bytes(application_, config_, job.reference.space, job.measured, request.input.input.sign,
                                    std::span(std::get_if<SigningScratch>(&job.scratch)->message));
  if (length == 0 || !digest(std::span(std::get_if<SigningScratch>(&job.scratch)->message).first(length),
                             std::span(std::get_if<SigningScratch>(&job.scratch)->hash))) {
    return RASP_SK_OP_INTERNAL_ERROR;
  }
  if (!refresh_clock()) {
    return RASP_SK_OP_BUSY;
  }
  {
    const std::scoped_lock lock(mutex_);
    std::uint64_t now = 0;
    const auto valid = sample(now) ? eligible(request, now) : RASP_SK_OP_CLOCK_UNAVAILABLE;
    if (valid != RASP_SK_OP_OK) {
      return valid;
    }
  }
  auto& decision = job_gate(job);
  const bool allowed = gate(request, decision);
  std::uint32_t written = 0;
  const auto status =
      allowed ? outcome(platform_->sign(
                    job.reference, std::span(std::get_if<SigningScratch>(&job.scratch)->message).first(length),
                    context(job), std::span(std::get_if<SigningScratch>(&job.scratch)->signature), written))
              : RASP_SK_OP_GATE_REJECTED;
  const std::scoped_lock lock(mutex_);
  request.result.gate = decision;
  request.result.gate_present = 1;
  if (status != RASP_SK_OP_OK) {
    return status;
  }
  if (written > 72 ||
      !valid_signature(std::span(std::get_if<SigningScratch>(&job.scratch)->signature).first(written))) {
    return RASP_SK_OP_PLATFORM_ERROR;
  }
  request.result.value_tag = RASP_SK_VALUE_SIGNATURE;
  auto& signature = request.result.value.signature;
  signature.key_id = job.reference.key_id;
  signature.algorithm = 1;
  signature.der_length = written;
  std::ranges::copy(std::span(std::get_if<SigningScratch>(&job.scratch)->hash),
                    std::span(signature.message_sha256).begin());
  std::ranges::copy(std::span(std::get_if<SigningScratch>(&job.scratch)->signature).first(written),
                    std::span(signature.der).begin());
  return RASP_SK_OP_OK;
}
std::uint32_t Service::erase(Job& job) {
  auto& request = std::span{requests_}[job.request];
  {
    const std::scoped_lock lock(mutex_);
    candidate_ = manifest_;
    for (const auto& key : std::span(request.target_ids).first(request.target_count)) {
      const auto index = record_index(key);
      if (index < 32) {
        std::span{candidate_.records}[index].state = KeyState::kDeletePending;
      }
    }
    request.result.value_tag = RASP_SK_VALUE_DELETION;
    request.result.value.deletion = {};
    request.result.value.deletion.requested = request.target_count;
    request.result.value.deletion.remaining = request.target_count;
  }
  auto status = persist(job);
  if (status != RASP_SK_OP_OK) {
    return status;
  }
  progress(job, RASP_SK_TOMBSTONES_DURABLE, RASP_SK_EFFECT_UNKNOWN);
  for (const auto& key : std::span(request.target_ids).first(request.target_count)) {
    {
      const std::scoped_lock lock(mutex_);
      reference(job, key, request.space);
    }
    if (platform_->erase(job.reference) == RASP_SK_OP_OK) {
      const std::scoped_lock lock(mutex_);
      const auto index = record_index(key);
      if (index < 32) {
        std::span{candidate_.records}[index] = {};
        std::span{blocked_}[index] = false;
      }
      ++request.result.value.deletion.confirmed_absent;
      --request.result.value.deletion.remaining;
    }
  }
  status = persist(job);
  const std::scoped_lock lock(mutex_);
  if (status != RASP_SK_OP_OK || request.result.value.deletion.remaining != 0) {
    request.result.effect = RASP_SK_EFFECT_PARTIAL;
    return RASP_SK_OP_CLEANUP_PENDING;
  }
  request.result.durability = RASP_SK_DELETION_CONFIRMED;
  request.result.effect =
      request.input.operation == RASP_SK_RESET_NAMESPACE ? RASP_SK_NAMESPACE_EMPTY : RASP_SK_KEY_ABSENT;
  std::span{namespaces_}[request.space].resetting = std::ranges::any_of(requests_, [&](const auto& other) {
    return &other != &request && other.used && !other.terminal && other.space == request.space &&
           other.input.operation == RASP_SK_RESET_NAMESPACE;
  });
  request.cleanup = false;
  return RASP_SK_OP_OK;
}

void Service::finish(Job& job, std::uint32_t status) {
  if (std::span{requests_}[job.request].input.operation == RASP_SK_SIGN) {
    platform_->release(context(job));
  }
  const bool refreshed = refresh_clock();
  Posts posts;
  {
    const std::scoped_lock lock(mutex_);
    const auto index = job.request;
    auto& request = std::span{requests_}[index];
    std::uint64_t now = 0;
    if (!refreshed || !sample(now)) {
      status = RASP_SK_OP_CLOCK_UNAVAILABLE;
    } else if (request.final_status != RASP_SK_OP_OK || now >= request.deadline || state_ != State::kReady) {
      status = RASP_SK_OP_CANCELLED;
      if (request.final_status != RASP_SK_OP_OK) {
        status = request.final_status;
      } else if (now >= request.deadline) {
        status = RASP_SK_OP_EXPIRED;
      }
    }
    if (status == RASP_SK_OP_OK &&
        (request.input.operation == RASP_SK_CREATE || request.input.operation == RASP_SK_REOPEN) &&
        !handle(request, job.measured, now)) {
      status = RASP_SK_OP_RESOURCE_EXHAUSTED;
    }
    if (status == RASP_SK_OP_OK && request.input.operation == RASP_SK_DESCRIBE) {
      request.result.value_tag = RASP_SK_VALUE_INFO;
      request.result.value.info = job.measured;
    }
    if (status != RASP_SK_OP_OK) {
      fail(request, status);
    } else {
      request.result.operation_status = RASP_SK_OP_OK;
      request.terminal = true;
    }
    if (job.cleanup) {
      request.cleanup = false;
    }
    if (mutates(request)) {
      mutation_ = false;
    }
    if (job.prompt) {
      prompt_ = false;
    }
    clear(job);
    retire(index);
    dispatch(posts);
  }
  post(posts);
}
void Service::close(Job& job, EntryLease& entry) {
  if (!entry.wait_exclusive()) {
    const std::scoped_lock lock(mutex_);
    clear(job);
    return;
  }
  {
    const std::scoped_lock lock(mutex_);
    candidate_ = manifest_;
    for (std::size_t index = 0; index < 32; ++index) {
      if (std::span{blocked_}[index] && std::span{candidate_.records}[index].state != KeyState::kEmpty) {
        std::span{candidate_.records}[index].state = KeyState::kDeletePending;
      }
    }
  }
  if (storage_owned_ && !storage_fault_ && encode_manifest(candidate_, job_bytes(job)) &&
      platform_->persist(job_bytes(job)) == RASP_SK_OP_OK) {
    const std::scoped_lock lock(mutex_);
    manifest_ = candidate_;
  }
  const bool released = !storage_owned_ || platform_->close_storage();
  const std::scoped_lock lock(mutex_);
  storage_owned_ = !released;
  if (released) {
    state_ = State::kClosed;
    last_closed_ = client_;
    for (std::size_t index = 0; index < requests_.size(); ++index) {
      std::span{requests_}[index].taken = true;
      retire(index);
    }
  }
  clear(job);
}
void Service::run(const RaspScopedKeyTokenV1& value, EntryLease& entry) {
  Job* job = nullptr;
  {
    const std::scoped_lock lock(mutex_);
    auto* const found = std::ranges::find_if(
        jobs_, [&](const auto& candidate) { return candidate.used && same(candidate.token, value); });
    if (found == jobs_.end() || found->running || !found->posted) {
      return;
    }
    found->running = true;
    found->posted = false;
    job = &*found;
  }
  if (job->closing) {
    close(*job, entry);
    return;
  }
  auto& request = std::span{requests_}[job->request];
  std::uint32_t status = RASP_SK_OP_CLOCK_UNAVAILABLE;
  const bool refreshed = refresh_clock();
  {
    const std::scoped_lock lock(mutex_);
    std::uint64_t now = 0;
    if (refreshed && sample(now)) {
      status = eligible(request, now);
    }
    if (job->cleanup || request.input.operation == RASP_SK_DELETE ||
        request.input.operation == RASP_SK_RESET_NAMESPACE) {
      status = RASP_SK_OP_OK;
    }
  }
  if (status == RASP_SK_OP_OK) {
    if (job->cleanup || request.input.operation >= RASP_SK_DELETE) {
      status = erase(*job);
    } else if (request.input.operation == RASP_SK_CREATE) {
      status = create(*job);
    } else if (request.input.operation == RASP_SK_SIGN) {
      status = sign(*job);
    } else {
      status = describe(*job);
    }
  }
  Posts resumed;
  bool yielding = false;
  {
    const std::scoped_lock lock(mutex_);
    if (job->yielded_for_auth) {
      job->yielded_for_auth = false;
      job->running = false;
      yielding = true;
      dispatch(resumed);
    }
  }
  if (yielding) {
    post(resumed);
    return;
  }
  finish(*job, status);
}
void Service::auth(const RaspScopedKeyTokenV1& value, std::uint32_t status) {
  Posts posts;
  {
    const std::scoped_lock lock(mutex_);
    auto* const found = std::ranges::find_if(
        jobs_, [&](const auto& job) { return job.used && job.auth_pending && same(job.token, value); });
    if (found == jobs_.end()) {
      return;
    }
    found->auth_pending = false;
    found->authenticated = status == RASP_SK_OP_OK;
    if (!found->authenticated) {
      fail(std::span{requests_}[found->request], outcome(status));
    }
    dispatch(posts);
  }
  post(posts);
}
void run_job(const RaspScopedKeyTokenV1& job) {
  EntryLease entry;
  Service* owner = entry.get();
  if (owner != nullptr) {
    owner->run(job, entry);
  }
}
void authenticated(const RaspScopedKeyTokenV1& job, std::uint32_t status) {
  EntryLease const entry;
  Service* owner = entry.get();
  if (owner != nullptr) {
    owner->auth(job, status);
  }
}
}  // namespace rasp::keys
