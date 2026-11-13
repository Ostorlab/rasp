#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <gtest/gtest.h>
#include <iostream>
#include <string_view>
#include <variant>

#include "encoding.h"
#include "entry.h"
#if defined(__linux__) && !defined(RASP_KEYS_TEST_REPORT_ONLY)
#include "contention.h"
#include "local_policy_state.h"
#endif
#include <memory>
#include <span>

#include "manifest.h"
#include "platform.h"
#include "rasp/local_policy_host.h"
#include "rasp/scoped_key.h"
#include "support.h"
namespace {
rasp::keys::PlatformDiagnostic no_diagnostic() { return {}; }
/// Only OS boundaries are replaced; all Service, entries and real policy code are linked unchanged.
struct BoundaryState {
  fixture::Provider os;
  bool absent_lock = false;
  bool delayed_prompt = false;
  bool inline_query = false;
  std::atomic<bool> scratch_leased{false};
  std::function<void()> during_release_wait;
  bool reject_after_prepare = false;
  bool numeric_error = false;
  bool collision = false;
  bool sentinel_created = false;
  rasp::keys::KeyReference captured{};
  RaspScopedKeyInfoV1 sentinel{};
  RaspScopedKeyTokenV1 auth_job{};
  rasp::keys::KeyReference auth_key{};
  std::span<std::uint8_t> auth_context;
  RaspLocalGateResultV1 last_gate{};
  using Scratch = std::variant<rasp::keys::PromptCheck, RaspScopedKeyTakeResultV1>;
  Scratch scratch;
  static_assert(sizeof(Scratch) == 2608);
  std::uint32_t query_status = RASP_SK_OP_NOT_READY;
  std::uint32_t launch_status = RASP_SK_OP_OK;
  rasp::keys::PlatformDiagnostic launch_diagnostic;
  bool started = false;
  std::function<void(RaspScopedKeyInfoV1&, rasp::keys::CreationReceipt&)> after_create;
  std::uint32_t primitive_calls = 0;
};
class Boundary final : public rasp::keys::Platform {
 private:
  BoundaryState state_;

 public:
  [[nodiscard]] BoundaryState& state() { return state_; }
  [[nodiscard]] rasp::keys::PromptCheck& prompt() { return *std::get_if<rasp::keys::PromptCheck>(&state_.scratch); }
  void release_scratch() {
    state().scratch_leased.store(false, std::memory_order_release);
    state().scratch_leased.notify_all();
  }
  void acknowledge(std::uint32_t status) {
    if (state().query_status != RASP_SK_OP_OK) {
      rasp::keys::authenticated(state().auth_job, state().query_status, no_diagnostic(),
                                prompt().gate_present == 1 ? &prompt() : nullptr);
    } else if (state().launch_status != RASP_SK_OP_OK) {
      rasp::keys::authenticated(state().auth_job, state().launch_status, state().launch_diagnostic);
    } else {
      rasp::keys::authenticated(state().auth_job, status);
    }
    release_scratch();
  }
  bool main_thread() override { return state().os.main_thread(); }
  bool random(std::span<std::uint8_t> out) override { return state().os.random(out); }
  bool clock(std::uint64_t& out) override { return state().os.clock(out); }
  std::uint32_t open_storage(rasp::keys::Application& a, std::span<std::uint8_t> f, std::uint32_t& n,
                             bool& e) override {
    return state().os.open_storage(a, f, n, e);
  }
  std::uint32_t persist(std::span<const std::uint8_t> f, rasp::keys::PlatformDiagnostic& diagnostic) override {
    return state().os.persist(f, diagnostic);
  }
  bool close_storage() override { return state().os.close_storage(); }
  bool schedule(const RaspScopedKeyTokenV1& t) override { return state().os.schedule(t); }
  std::uint32_t create(const rasp::keys::KeyReference& k, RaspScopedKeyInfoV1& out,
                       rasp::keys::CreationReceipt& receipt, rasp::keys::PlatformDiagnostic& diagnostic) override {
    state().captured = k;
    if (state().collision) {
      state().sentinel = out;
      rasp::keys::CreationReceipt foreign;
      EXPECT_EQ(state().os.create(k, state().sentinel, foreign, diagnostic), RASP_SK_OP_OK);
      receipt = {};
      state().sentinel_created = true;
      return RASP_SK_OP_PLATFORM_ERROR;
    }
    const auto s = state().os.create(k, out, receipt, diagnostic);
    if (state().absent_lock) {
      out.provenance.lock_observed_present = 0;
      out.provenance.lock_observed = 0;
    }
    if (state().after_create) {
      state().after_create(out, receipt);
    }
    return s;
  }
  std::uint32_t describe(const rasp::keys::KeyReference& k, RaspScopedKeyInfoV1& out,
                         rasp::keys::PlatformDiagnostic& diagnostic) override {
    const auto status = state().os.describe(k, out, diagnostic);
    if (state().absent_lock) {
      out.provenance.lock_observed_present = 0;
      out.provenance.lock_observed = 0;
    }
    return status;
  }
  std::uint32_t authenticate(const RaspScopedKeyTokenV1& j, const rasp::keys::KeyReference& k,
                             std::span<std::uint8_t> c, rasp::keys::PlatformDiagnostic& diagnostic) override {
    state().auth_job = j;
    state().auth_key = k;
    state().auth_context = c;
    if (state().inline_query) {
      start_prompt();
      if (state().query_status != RASP_SK_OP_OK) {
        acknowledge(state().query_status);
        return RASP_SK_OP_OK;
      }
      diagnostic = state().launch_diagnostic;
      return state().launch_status;
    }
    if (!state().delayed_prompt) {
      return state().os.authenticate(j, k, c, diagnostic);
    }
    return RASP_SK_OP_OK;
  }
  std::uint32_t prepare_sign(const rasp::keys::KeyReference& k, std::span<const std::uint8_t> m,
                             std::span<std::uint8_t> c, rasp::keys::PlatformDiagnostic& diagnostic) override {
    const auto status = state().os.prepare_sign(k, m, c, diagnostic);
    if (state().reject_after_prepare) {
      fixture::publish(7);
      RaspLocalGateRequestV1 q{};
      q.abi_version = 1;
      q.struct_size = sizeof(q);
      std::memcpy(std::span(q.operation).data(), "append_demo_receipt", 19);
      constexpr std::string_view kHex = "0123456789abcdef";
      for (std::size_t i = 0; i < 32; ++i) {
        std::span(q.expected_policy_sha256)[i * 2] = kHex[std::span(k.space.expected_policy_sha256)[i] >> 4U];
        std::span(q.expected_policy_sha256)[(i * 2) + 1] = kHex[std::span(k.space.expected_policy_sha256)[i] & 15U];
      }
      EXPECT_EQ(rasp_local_policy_gate_v1(&q, sizeof(q), &state().last_gate, sizeof(state().last_gate)), RASP_LOCAL_OK);
      return status;
    }
    return status;
  }
  std::uint32_t sign(const rasp::keys::KeyReference& k, std::span<std::uint8_t> c, std::span<std::uint8_t> d,
                     std::uint32_t& n, rasp::keys::PlatformDiagnostic& diagnostic) override {
    if (state().numeric_error) {
      diagnostic.present = 1;
      diagnostic.error.platform = RASP_SK_PLATFORM_ANDROID;
      diagnostic.error.domain = RASP_SK_ANDROID_KEYSTORE_ERROR;
      diagnostic.error.numeric_code_present = 1;
      diagnostic.error.numeric_code = -73;
      return RASP_SK_OP_PLATFORM_ERROR;
    }
    ++state().primitive_calls;
    return state().os.sign(k, c, d, n, diagnostic);
  }
  std::uint32_t erase(const rasp::keys::KeyReference& k, const rasp::keys::CleanupProof& proof,
                      rasp::keys::PlatformDiagnostic& diagnostic) override {
    return state().os.erase(k, proof, diagnostic);
  }
  void cancel(const RaspScopedKeyTokenV1& j) override { state().os.cancel(j); }
  void release(std::span<std::uint8_t> c) override {
    if (state().scratch_leased.load(std::memory_order_acquire) && state().during_release_wait) {
      state().during_release_wait();
    }
    while (state().scratch_leased.load(std::memory_order_acquire)) {
      state().scratch_leased.wait(true, std::memory_order_acquire);
    }
    state().os.release(c);
  }
  bool sentinel_present() {
    auto info = state().sentinel;
    rasp::keys::PlatformDiagnostic diagnostic;
    return state().os.describe(state().captured, info, diagnostic) == RASP_SK_OP_OK;
  }
  void refuse_queued_prompt(bool unavailable) {
    fixture::publish(unavailable ? 0 : 7, unavailable);
    start_prompt();
    acknowledge(state().query_status);
  }
  void start_prompt() {
    ASSERT_FALSE(state().started);
    state().started = true;
    bool unleased = false;
    ASSERT_TRUE(state().scratch_leased.compare_exchange_strong(unleased, true));
    state().query_status = rasp::keys::prompt_eligibility(state().auth_job, prompt());
    state().last_gate = prompt().gate;
    if (state().query_status == RASP_SK_OP_OK) {
      state().launch_status =
          state().os.authenticate(state().auth_job, state().auth_key, state().auth_context, state().launch_diagnostic);
      release_scratch();
    }
  }
};
#if defined(__linux__) && !defined(RASP_KEYS_TEST_REPORT_ONLY)
/// Pauses only the calling test thread after an actual successful production mutex acquisition.
class MutexPause {
 public:
  MutexPause() : released_(release_.get_future().share()) {}
  MutexPause(const MutexPause&) = delete;
  MutexPause& operator=(const MutexPause&) = delete;
  MutexPause(MutexPause&&) = delete;
  MutexPause& operator=(MutexPause&&) = delete;
  ~MutexPause() { release(); }
  void arm() { fixture::after_next_mutex(arrived, this); }
  void wait() { EXPECT_EQ(entered_.get_future().wait_for(std::chrono::seconds(2)), std::future_status::ready); }
  void release() {
    if (!done_) {
      done_ = true;
      release_.set_value();
    }
  }

 private:
  static void arrived(void* value) {
    auto* pause = static_cast<MutexPause*>(value);
    pause->entered_.set_value();
    pause->released_.wait();
  }
  std::promise<void> entered_;
  std::promise<void> release_;
  std::shared_future<void> released_;
  bool done_ = false;
};
#endif
struct AdapterState {
  Boundary p;
  RaspScopedKeyClientSpecV1 spec{};
  RaspScopedKeyClientOpenedV1 opened{};
  std::unique_ptr<RaspScopedKeySubmitV1> input = std::make_unique<RaspScopedKeySubmitV1>();
  std::unique_ptr<RaspScopedKeyTakeResultV1> result = std::make_unique<RaspScopedKeyTakeResultV1>();
};
class AdapterSeams : public ::testing::Test {
 private:
  AdapterState state_;

 protected:
  [[nodiscard]] AdapterState& state() { return state_; }
  void SetUp() override {
    fixture::ticks().fetch_add(1000000);
    fixture::publish();
    fixture::publish();
    ASSERT_TRUE(rasp::keys::attach_platform(state().p));
    state().spec = fixture::config();
    open();
  }
  void TearDown() override {
    state().p.release_scratch();
    for (const auto& j : state().p.state().os.state().auth_jobs) {
      rasp::keys::authenticated(j, RASP_SK_OP_CANCELLED);
    }
    close();
    state().p.state().os.state().erase_fail = false;
    state().p.state().os.state().close_fail = false;
    state().p.state().os.drain();
    EXPECT_TRUE(rasp::keys::detach_platform(state().p));
  }
  void open() {
    ASSERT_EQ(
        rasp_scoped_key_client_open_v1(&state().spec, sizeof(state().spec), &state().opened, sizeof(state().opened)),
        RASP_SK_CALL_OK);
    ASSERT_EQ(state().opened.operation_status, RASP_SK_OP_OK);
  }
  void close() {
    RaspScopedKeyControlV1 c{};
    c.abi_version = 1;
    c.struct_size = sizeof(c);
    c.client = state().opened.client;
    c.action = RASP_SK_CLOSE_CLIENT;
    RaspScopedKeyControlResultV1 o{};
    EXPECT_EQ(rasp_scoped_key_control_v1(&c, sizeof(c), &o, sizeof(o)), RASP_SK_CALL_OK);
    state().p.state().os.drain();
  }
  RaspScopedKeyTokenV1 submit(std::uint32_t op, RaspScopedKeyTokenV1 key = {}) {
    *state().input = {};
    state().input->abi_version = 1;
    state().input->struct_size = sizeof(*state().input);
    state().input->client = state().opened.client;
    state().input->namespace_handle = state().opened.namespaces[0].namespace_handle;
    state().input->operation = op;
    state().input->request_ttl_ms = 60000;
    if (op == RASP_SK_SIGN) {
      auto& s = state().input->input.sign;
      s.key = key;
      s.expected_purpose_length = 19;
      std::memcpy(std::span(s.expected_purpose).data(), "transaction_receipt", 19);
      s.audience_length = 16;
      std::memcpy(std::span(s.audience).data(), "receipts.example", 16);
      s.transaction_id[0] = 1;
      s.challenge[0] = 2;
      s.transaction_length = 4;
      std::memcpy(std::span(s.transaction).data(), "data", 4);
      s.interaction = RASP_SK_ALLOW_SYSTEM_BIOMETRY;
    }
    if (op == RASP_SK_REOPEN || op == RASP_SK_DELETE) {
      state().input->input.key_id = key;
    }
    RaspScopedKeyAdmissionV1 out{};
    EXPECT_EQ(rasp_scoped_key_submit_v1(state().input.get(), sizeof(*state().input), &out, sizeof(out)),
              RASP_SK_CALL_OK);
    EXPECT_EQ(out.admission_state, RASP_SK_ACCEPTED);
    return out.request;
  }
  void take(const RaspScopedKeyTokenV1& r) {
    RaspScopedKeyTakeRequestV1 q{};
    q.abi_version = 1;
    q.struct_size = sizeof(q);
    q.client = state().opened.client;
    q.request = r;
    ASSERT_EQ(rasp_scoped_key_take_v1(&q, sizeof(q), state().result.get(), sizeof(*state().result)), RASP_SK_CALL_OK);
  }
  RaspScopedKeyValueKeyV1 key() {
    const auto r = submit(RASP_SK_CREATE);
    state().p.state().os.drain();
    take(r);
    EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
    return state().result->completion.value.key;
  }
  void cancel(const RaspScopedKeyTokenV1& request) {
    RaspScopedKeyControlV1 c{};
    c.abi_version = 1;
    c.struct_size = sizeof(c);
    c.client = state().opened.client;
    c.action = RASP_SK_CANCEL;
    c.target = request;
    RaspScopedKeyControlResultV1 out{};
    EXPECT_EQ(rasp_scoped_key_control_v1(&c, sizeof(c), &out, sizeof(out)), RASP_SK_CALL_OK);
  }
#if defined(__linux__) && !defined(RASP_KEYS_TEST_REPORT_ONLY)
  void final_mutex_refusal(bool take_before_ack) {
    biometry();
    const auto k = key();
    state().p.state().delayed_prompt = true;
    const auto r = submit(RASP_SK_SIGN, k.key_handle);
    ASSERT_TRUE(state().p.state().os.step());
    fixture::publish(7);
    MutexPause pause;
    std::promise<void> trigger;
    auto triggered = trigger.get_future();
    bool signalled = false;
    auto control = std::async(std::launch::async, [&] {
      triggered.wait();
      pause.arm();
      cancel(r);
    });
    unsigned samples = 0;
    state().p.state().os.state().during_clock = [&] {
      if (++samples == 2) {
        signalled = true;
        trigger.set_value();
        pause.wait();
      }
    };
    state().p.start_prompt();
    state().p.state().os.state().during_clock = {};
    if (!signalled) {
      trigger.set_value();
      pause.wait();
    }
    EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_BUSY);
    EXPECT_EQ(state().p.prompt().gate_present, 1U);
    EXPECT_EQ(state().p.prompt().gate.action, RASP_LOCAL_DENY);
    EXPECT_EQ(state().p.prompt().gate_committed, 0U);
    EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
    pause.release();
    control.get();
    if (take_before_ack) {
      take(r);
      EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
      EXPECT_EQ(state().result->retained_jobs, 1U);
    }
    state().p.acknowledge(RASP_SK_OP_OK);
    state().p.state().os.drain();
    if (take_before_ack) {
      take(r);
      EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
      EXPECT_EQ(state().result->retained_jobs, 0U);
    } else {
      take(r);
      EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
      EXPECT_EQ(state().result->completion.gate.action, RASP_LOCAL_DENY);
      EXPECT_EQ(
          std::memcmp(&state().result->completion.gate, &state().p.prompt().gate, sizeof(state().p.state().last_gate)),
          0);
    }
  }
#endif
  void witness_failure(bool published) {
    auto& os = state().p.state().os.state();
    os.persist_fail_at = static_cast<int>(os.persists.load() + 2);
    os.publish_before_error = published;
    os.erase_fail = true;
    const auto r = submit(RASP_SK_CREATE);
    state().p.state().os.drain();
    take(r);
    EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_STORAGE_UNAVAILABLE);
    EXPECT_EQ(state().result->completion.durability, RASP_SK_DURABILITY_UNKNOWN);
    EXPECT_EQ(state().result->completion.effect, RASP_SK_EFFECT_UNKNOWN);
    const auto disk = os.disk;
    auto manifest = std::make_unique<rasp::keys::Manifest>();
    ASSERT_TRUE(rasp::keys::decode_manifest(disk, *manifest));
    EXPECT_EQ(manifest->records[0].state, rasp::keys::KeyState::kReserved);
    EXPECT_EQ(manifest->records[0].info.public_key_x963[0], published ? 4U : 0U);
    EXPECT_EQ(state().p.state().os.stored_keys(), 1U);
    RaspScopedKeyAdmissionV1 denied{};
    EXPECT_EQ(rasp_scoped_key_submit_v1(state().input.get(), sizeof(*state().input), &denied, sizeof(denied)),
              RASP_SK_CALL_OK);
    EXPECT_EQ(denied.operation_status, RASP_SK_OP_STORAGE_UNAVAILABLE);
    close();
    EXPECT_EQ(os.disk, disk);
    os.persist_fail_at = -1;
    os.erase_fail = false;
    open();
    EXPECT_EQ(state().p.state().os.stored_keys(), published ? 0U : 1U);
    auto actual = std::make_unique<rasp::keys::Manifest>();
    ASSERT_TRUE(rasp::keys::decode_manifest(os.disk, *actual));
    EXPECT_EQ(actual->records[0].state, published ? rasp::keys::KeyState::kEmpty : rasp::keys::KeyState::kReserved);
  }
  void biometry() {
    close();
    state().spec = fixture::config(true);
    if (fixture::report_only()) {
      state().spec.namespaces[0].gate_mode = RASP_SK_EXPLICIT_ADVISORY;
    }
    open();
  }
};
TEST_F(AdapterSeams, r1_whenDefaultGetterAbsent_doesNotInventObservedFalse) {
  state().p.state().absent_lock = true;
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  std::cout << "R1 default absent observation: status=" << state().result->completion.operation_status
            << " erase_calls=" << state().p.state().os.state().erases.load() << "\n";
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
}
TEST_F(AdapterSeams, r1_whenStrictObservationAbsent_remainsRejected) {
  close();
  state().spec = fixture::config();
  state().spec.namespaces[0].lock_requirement = RASP_SK_UNLOCKED_REQUIRED;
  open();
  state().p.state().absent_lock = true;
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  EXPECT_NE(state().result->completion.operation_status, RASP_SK_OP_OK);
}
TEST_F(AdapterSeams, r2_whenQueuedMainStartAfterExpiry_neverPrompts) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  fixture::ticks().fetch_add(UINT64_C(60000000000));
  state().p.start_prompt();
  std::cout << "R2 queued prompt after TTL: prompts=" << state().p.state().os.state().prompts.load()
            << " queue=" << state().p.state().os.state().queue.size() << "\n";
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_EXPIRED);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
}
TEST_F(AdapterSeams, r2_whenQueuedMainStartStillValid_signsOnce) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.start_prompt();
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 1U);
  EXPECT_EQ(state().p.state().primitive_calls, 1U);
  EXPECT_EQ(state().result->completion.gate.action, fixture::report_only() ? RASP_LOCAL_REPORT : RASP_LOCAL_ALLOW);
}
TEST_F(AdapterSeams, r2_whenQueuedUnexpiredGateBecomesDeny_transfersActualRefusal) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.refuse_queued_prompt(false);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  std::cout << "R2 unexpired new DENY: prompt0 real_action=" << state().p.state().last_gate.action
            << " transferred=" << state().result->completion.gate.action
            << " sequence=" << static_cast<unsigned long long>(state().p.state().last_gate.sequence) << "/"
            << static_cast<unsigned long long>(state().result->completion.gate.sequence) << "\n";
  EXPECT_EQ(state().result->completion.gate.action, state().p.state().last_gate.action);
  EXPECT_EQ(
      std::memcmp(&state().result->completion.gate, &state().p.state().last_gate, sizeof(state().p.state().last_gate)),
      0);
  EXPECT_EQ(state().result->completion.gate.sequence, state().p.state().last_gate.sequence);
}
TEST_F(AdapterSeams, r2_whenQueuedUnexpiredGateBecomesUnavailable_transfersActualRefusal) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.refuse_queued_prompt(true);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  std::cout << "R2 unexpired new unavailable: prompt0 real_action=" << state().p.state().last_gate.action
            << " transferred=" << state().result->completion.gate.action
            << " sequence=" << static_cast<unsigned long long>(state().p.state().last_gate.sequence) << "/"
            << static_cast<unsigned long long>(state().result->completion.gate.sequence) << "\n";
  EXPECT_EQ(state().result->completion.gate.action, state().p.state().last_gate.action);
  EXPECT_EQ(
      std::memcmp(&state().result->completion.gate, &state().p.state().last_gate, sizeof(state().p.state().last_gate)),
      0);
  EXPECT_EQ(state().result->completion.gate.sequence, state().p.state().last_gate.sequence);
}
TEST_F(AdapterSeams, r3_whenProviderFinalGateRejects_preservesActualLastGate) {
  const auto k = key();
  state().p.state().reject_after_prepare = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  state().p.state().os.drain();
  take(r);
  std::cout << "R3 final real gate=" << state().p.state().last_gate.action
            << " completion gate=" << state().result->completion.gate.action
            << " status=" << state().result->completion.operation_status
            << " primitives=" << state().p.state().primitive_calls << "\n";
  EXPECT_EQ(state().p.state().last_gate.action, RASP_LOCAL_DENY);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  EXPECT_EQ(state().result->completion.gate.action, state().p.state().last_gate.action);
  EXPECT_EQ(
      std::memcmp(&state().result->completion.gate, &state().p.state().last_gate, sizeof(state().p.state().last_gate)),
      0);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
}
TEST_F(AdapterSeams, r4_whenBoundaryHasNumericFailure_transfersToPublicCompletion) {
  const auto k = key();
  state().p.state().numeric_error = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  state().p.state().os.drain();
  take(r);
  std::cout << "R4 simulated OS error -73: status=" << state().result->completion.operation_status
            << " error_present=" << state().result->completion.platform_error_present << "\n";
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_PLATFORM_ERROR);
  EXPECT_EQ(state().result->completion.platform_error_present, 1U);
  EXPECT_EQ(state().result->completion.platform_error.numeric_code, -73);
}
TEST_F(AdapterSeams, r5_whenCreateRefusesOccupiedAlias_neverDeletesForeignKey) {
  state().p.state().collision = true;
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  const bool present = state().p.sentinel_present();
  std::cout << "R5 immediate collision: sentinel_generated=" << state().p.state().sentinel_created
            << " erase_calls=" << state().p.state().os.state().erases.load() << " sentinel_present=" << present << "\n";
  EXPECT_TRUE(present);
}
TEST_F(AdapterSeams, r5_whenUnprovedReservationReloads_neverDeletesOccupiedAlias) {
  state().p.state().collision = true;
  state().p.state().os.state().erase_fail = true;
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  ASSERT_TRUE(state().p.sentinel_present());
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
  close();
  state().p.state().collision = false;
  state().p.state().os.state().erase_fail = false;
  open();
  const bool present = state().p.sentinel_present();
  std::cout << "R5 durable close/reopen recovery: sentinel_present=" << present
            << " erase_calls=" << state().p.state().os.state().erases.load() << "\n";
  EXPECT_TRUE(present);
}
TEST_F(AdapterSeams, ordinary_whenUnchangedProviderAndRealGate_signsVerifiedMessage) {
  const auto k = key();
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  const auto expected = fixture::message(k.info, state().spec, state().input->input.sign);
  state().p.state().os.drain();
  take(r);
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_TRUE(fixture::verify(k.info, expected, state().result->completion.value.signature));
}
TEST_F(AdapterSeams, r1_whenDefaultAbsenceReopens_preservesTruthAndPublicPoint) {
  state().p.state().absent_lock = true;
  const auto k = key();
  close();
  open();
  const auto r = submit(RASP_SK_REOPEN, k.info.key_id);
  state().p.state().os.drain();
  take(r);
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().result->completion.value.key.info.provenance.lock_observed_present, 0U);
  EXPECT_EQ(state().result->completion.value.key.info.provenance.lock_observed, RASP_SK_LOCK_REQUIREMENT_UNKNOWN);
  EXPECT_TRUE(std::ranges::equal(state().result->completion.value.key.info.public_key_x963, k.info.public_key_x963));
}
TEST_F(AdapterSeams, r1_whenAbsentObservationHasNonzeroValue_rejectsAndCleansOnlyOwnedKey) {
  state().p.state().after_create = [](auto& info, auto&) {
    info.provenance.lock_observed_present = 0;
    info.provenance.lock_observed = RASP_SK_PLATFORM_DEFAULT;
  };
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_PLATFORM_ERROR);
  EXPECT_EQ(state().p.state().os.state().erases.load(), 1U);
}
TEST_F(AdapterSeams, r1_whenStrictActualReadbackMatches_acceptsWithoutWeakeningHardwareMinima) {
  close();
  state().spec = fixture::config();
  state().spec.namespaces[0].lock_requirement = RASP_SK_UNLOCKED_REQUIRED;
  open();
  const auto k = key();
  EXPECT_EQ(k.info.provenance.lock_observed_present, 1U);
  EXPECT_EQ(k.info.provenance.lock_observed, RASP_SK_UNLOCKED_REQUIRED);
  auto changed = k.info;
  changed.provenance.lock_observed = RASP_SK_PLATFORM_DEFAULT;
  EXPECT_FALSE(rasp::keys::valid_info(changed, state().spec.namespaces[0]));
  changed = k.info;
  changed.provenance.auth_observed = RASP_SK_CURRENT_BIOMETRY_EACH_REQUEST;
  EXPECT_FALSE(rasp::keys::valid_info(changed, state().spec.namespaces[0]));
  auto hardware = state().spec.namespaces[0];
  hardware.backend_requirement = RASP_SK_HARDWARE_REQUIRED;
  changed = k.info;
  changed.backend_requirement = hardware.backend_requirement;
  EXPECT_FALSE(rasp::keys::valid_info(changed, hardware));
  changed = k.info;
  changed.provenance.backend = RASP_SK_APPLE_KEYCHAIN;
  changed.provenance.source = RASP_SK_APPLE_ATTRIBUTES_AND_CREATION;
  changed.provenance.lock_observed_present = 0;
  changed.provenance.lock_observed = 0;
  EXPECT_FALSE(rasp::keys::valid_info(changed, state().spec.namespaces[0]));
}
TEST_F(AdapterSeams, r2_whenRegistryWriterContends_refusesWithoutPromptThenAccountsOnce) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  {
    rasp::keys::EntryLease writer;
    ASSERT_TRUE(writer.try_exclusive());
    state().p.start_prompt();
    EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_BUSY);
    EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  }
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_BUSY);
  EXPECT_EQ(state().result->retained_jobs, 0U);
}
TEST_F(AdapterSeams, r2_whenClockCancelsAfterActualGate_commitsRefusalToExactRequest) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  unsigned samples = 0;
  state().p.state().os.state().during_clock = [&] {
    if (++samples == 2) {
      RaspScopedKeyControlV1 c{};
      c.abi_version = 1;
      c.struct_size = sizeof(c);
      c.client = state().opened.client;
      c.action = RASP_SK_CANCEL;
      c.target = r;
      RaspScopedKeyControlResultV1 out{};
      EXPECT_EQ(rasp_scoped_key_control_v1(&c, sizeof(c), &out, sizeof(out)), RASP_SK_CALL_OK);
    }
  };
  state().p.start_prompt();
  state().p.state().os.state().during_clock = {};
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_CANCELLED);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
  EXPECT_EQ(state().result->completion.gate_present, 1U);
}
TEST_F(AdapterSeams, r2_whenClockClosesAfterActualGate_neverLaunchesOrReleasesStorageEarly) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  unsigned samples = 0;
  state().p.state().os.state().during_clock = [&] {
    if (++samples == 2) {
      close();
    }
  };
  state().p.start_prompt();
  state().p.state().os.state().during_clock = {};
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_CANCELLED);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  EXPECT_TRUE(state().p.state().os.state().storage_owned);
  EXPECT_FALSE(rasp::keys::detach_platform(state().p));
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  EXPECT_FALSE(state().p.state().os.state().storage_owned);
}
TEST_F(AdapterSeams, r2_whenClockReadFails_refusesAndReleasesOriginalContext) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.state().os.state().clock_fail = true;
  state().p.start_prompt();
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  EXPECT_EQ(state().result->retained_jobs, 0U);
}
TEST_F(AdapterSeams, r2_whenSuccessPayloadIsPassedAsAuth_cannotGrantAuthentication) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.start_prompt();
  rasp::keys::authenticated(state().p.state().auth_job, RASP_SK_OP_OK, no_diagnostic(), &state().p.prompt());
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->take_state, RASP_SK_PENDING);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().p.state().primitive_calls, 1U);
}
TEST_F(AdapterSeams, r2_whenOldFullTokenArrivesAfterReuse_cannotQueryOrAcknowledgeNewJob) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.start_prompt();
  const auto old_job = state().p.state().auth_job;
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  state().p.state().started = false;
  r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  auto old = std::make_unique<rasp::keys::PromptCheck>();
  EXPECT_EQ(rasp::keys::prompt_eligibility(old_job, *old), RASP_SK_OP_NOT_FOUND);
  rasp::keys::authenticated(old_job, RASP_SK_OP_OK);
  EXPECT_EQ(state().p.state().primitive_calls, 1U);
  state().p.start_prompt();
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().p.state().primitive_calls, 2U);
}
TEST_F(AdapterSeams, r3_whenPreparationCancelsOrExpiresUse_neverInvokesFinalPrimitive) {
  const auto k = key();
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  state().p.state().os.state().during_prepare = [] { fixture::ticks().fetch_add(UINT64_C(60000000000)); };
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_EXPIRED);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
}
TEST_F(AdapterSeams, r3_whenFinalPrimitiveFails_preservesActualFreshGateAndNumericError) {
  const auto k = key();
  state().p.state().numeric_error = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.gate_present, 1U);
  EXPECT_EQ(state().result->completion.gate.action, RASP_LOCAL_ALLOW);
  EXPECT_EQ(state().result->completion.platform_error.numeric_code, -73);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_PLATFORM_ERROR);
}
TEST_F(AdapterSeams, r4_whenCanonicalFieldsAreMalformed_neverExposesInventedDiagnostics) {
  const auto k = key();
  state().p.state().os.state().sign_status = RASP_SK_OP_PLATFORM_ERROR;
  auto& d = state().p.state().os.state().sign_diagnostic;
  d.present = 1;
  d.error.platform = RASP_SK_PLATFORM_ANDROID;
  d.error.domain = RASP_SK_APPLE_OSSTATUS_ERROR;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_PLATFORM_ERROR);
  EXPECT_EQ(state().result->completion.platform_error_present, 0U);
}
TEST_F(AdapterSeams, r4_whenSuccessfulCleanupHasNoDiagnostic_preservesActualCreationFailure) {
  state().p.state().os.state().create_status = RASP_SK_OP_PLATFORM_ERROR;
  auto& d = state().p.state().os.state().create_diagnostic;
  d.present = 1;
  d.error.platform = RASP_SK_PLATFORM_ANDROID;
  d.error.domain = RASP_SK_ANDROID_KEYSTORE_ERROR;
  d.error.numeric_code_present = 1;
  d.error.numeric_code = -11;
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.platform_error_present, 1U);
  EXPECT_EQ(state().result->completion.platform_error.numeric_code, -11);
}
TEST_F(AdapterSeams, r4_whenCleanupFailsWithNewMeaningfulError_latestActualFailureWins) {
  state().p.state().os.state().create_status = RASP_SK_OP_PLATFORM_ERROR;
  state().p.state().os.state().erase_fail = true;
  auto& d = state().p.state().os.state().create_diagnostic;
  d.present = 1;
  d.error.platform = RASP_SK_PLATFORM_ANDROID;
  d.error.domain = RASP_SK_ANDROID_KEYSTORE_ERROR;
  d.error.numeric_code_present = 1;
  d.error.numeric_code = -11;
  state().p.state().os.state().erase_diagnostic = d;
  state().p.state().os.state().erase_diagnostic.error.numeric_code = -12;
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
  EXPECT_EQ(state().result->completion.platform_error.numeric_code, -12);
}
TEST_F(AdapterSeams, r4_whenAsyncAuthHasActualNumericError_transfersOnceAndIgnoresDuplicate) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.start_prompt();
  rasp::keys::PlatformDiagnostic d;
  d.present = 1;
  d.error.platform = RASP_SK_PLATFORM_ANDROID;
  d.error.domain = RASP_SK_ANDROID_BIOMETRIC_ERROR;
  d.error.numeric_code_present = 1;
  d.error.numeric_code = 7;
  rasp::keys::authenticated(state().p.state().auth_job, RASP_SK_OP_AUTH_LOCKOUT, d);
  d.error.numeric_code = 8;
  rasp::keys::authenticated(state().p.state().auth_job, RASP_SK_OP_AUTH_LOCKOUT, d);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_AUTH_LOCKOUT);
  EXPECT_EQ(state().result->completion.platform_error.numeric_code, 7);
}
TEST_F(AdapterSeams, r5_whenMeasuredBindingIsInvalid_persistsOnlyTrustedWitnessThenCleansExactKey) {
  state().p.state().after_create = [](auto& info, auto&) {
    info.namespace_selector = 999;
    info.reserved[0] = 1;
  };
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_PLATFORM_ERROR);
  EXPECT_EQ(state().p.state().os.state().erases.load(), 1U);
  EXPECT_FALSE(state().p.sentinel_present());
}
TEST_F(AdapterSeams, r5_whenReceiptPointIsMalformed_retainsUnprovedOccupiedReservation) {
  state().p.state().after_create = [](auto&, auto& receipt) { receipt.point[0] = 3; };
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
  auto manifest = std::make_unique<rasp::keys::Manifest>();
  ASSERT_TRUE(rasp::keys::decode_manifest(state().p.state().os.state().disk, *manifest));
  EXPECT_EQ(manifest->records[0].state, rasp::keys::KeyState::kReserved);
  EXPECT_EQ(manifest->records[0].info.public_key_x963[0], 0U);
}

#if defined(__linux__) && !defined(RASP_KEYS_TEST_REPORT_ONLY)
TEST_F(AdapterSeams, r2_whenStateMutexIsContended_returnsWithoutWaitingForUi) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  MutexPause pause;
  auto control = std::async(std::launch::async, [&] {
    pause.arm();
    cancel(r);
  });
  pause.wait();
  auto query = std::async(std::launch::async, [&] {
    state().p.start_prompt();
    return state().p.state().query_status;
  });
  EXPECT_EQ(query.wait_for(std::chrono::milliseconds(100)), std::future_status::ready);
  pause.release();
  control.get();
  EXPECT_EQ(query.get(), RASP_SK_OP_BUSY);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
  EXPECT_EQ(state().result->retained_jobs, 0U);
}
TEST_F(AdapterSeams, r2_whenFinalMutexContends_workerRetainsActualRefusedGate) { final_mutex_refusal(false); }
TEST_F(AdapterSeams, r2_whenCancelledResultTransfersBeforeRefusalAck_neverWritesRetiredOutput) {
  final_mutex_refusal(true);
}
TEST_F(AdapterSeams, r2_whenActualPolicyMutexIsBusy_transfersFullNonOkGateWithoutPrompt) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  auto* owner = rasp::process_local_policy();
  ASSERT_NE(owner, nullptr);
  MutexPause pause;
  auto publication = std::async(std::launch::async, [&] {
    pause.arm();
    owner->begin_cycle();
  });
  pause.wait();
  state().p.start_prompt();
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_GATE_REJECTED);
  EXPECT_NE(state().p.prompt().gate_call_status, RASP_LOCAL_OK);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  pause.release();
  publication.get();
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  EXPECT_EQ(state().result->completion.gate_present, 1U);
  EXPECT_EQ(state().result->completion.gate.action, state().p.prompt().gate.action);
}
#endif

TEST_F(AdapterSeams, r2_whenQueryAndAuthCallbackPrecedeWorkerYield_resumesExactJobOnce) {
  biometry();
  const auto k = key();
  state().p.state().inline_query = true;
  state().p.state().os.state().immediate_auth = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 1U);
  EXPECT_EQ(state().p.state().os.state().queue.size(), 1U);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().p.state().primitive_calls, 1U);
  EXPECT_FALSE(state().p.state().scratch_leased.load());
}
TEST_F(AdapterSeams, r2_whenHandleExpiresBeforeQueuedRequest_neverStartsPrompt) {
  biometry();
  const auto k = key();
  fixture::ticks().fetch_add(UINT64_C(260000000000));
  fixture::publish();
  fixture::publish();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  fixture::ticks().fetch_add(UINT64_C(40000000000));
  state().p.start_prompt();
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_EXPIRED);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_EXPIRED);
}
TEST_F(AdapterSeams, r2_whenRefusalAckStillPinsSerializedScratch_releaseRetainsOriginalContextAndStorage) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  fixture::publish(7);
  state().p.start_prompt();
  ASSERT_EQ(state().p.state().query_status, RASP_SK_OP_GATE_REJECTED);
  ASSERT_TRUE(state().p.state().scratch_leased.load());
  std::promise<void> scheduled;
  std::promise<void> finish_post;
  const auto finish = finish_post.get_future().share();
  std::promise<void> releasing;
  state().p.state().during_release_wait = [&] { releasing.set_value(); };
  state().p.state().os.state().during_schedule = [&] {
    scheduled.set_value();
    finish.wait();
  };
  auto ack = std::async(std::launch::async, [&] { state().p.acknowledge(RASP_SK_OP_OK); });
  scheduled.get_future().wait();
  auto worker = std::async(std::launch::async, [&] { return state().p.state().os.step(); });
  EXPECT_EQ(releasing.get_future().wait_for(std::chrono::seconds(2)), std::future_status::ready);
  EXPECT_EQ(worker.wait_for(std::chrono::milliseconds(20)), std::future_status::timeout);
  EXPECT_TRUE(state().p.state().os.state().storage_owned);
  EXPECT_TRUE(state().p.state().scratch_leased.load());
  EXPECT_FALSE(rasp::keys::detach_platform(state().p));
  finish_post.set_value();
  ack.get();
  EXPECT_TRUE(worker.get());
  state().p.state().os.state().during_schedule = {};
  state().p.state().during_release_wait = {};
  EXPECT_FALSE(state().p.state().scratch_leased.load());
  take(r);
  EXPECT_EQ(state().result->completion.gate.action, RASP_LOCAL_DENY);
  EXPECT_EQ(state().result->retained_jobs, 0U);
}
TEST_F(AdapterSeams, r5_whenReceiptNamesDifferentCanonicalPoint_retainsUnprovedReservation) {
  state().p.state().after_create = [](auto&, auto& receipt) {
    const auto point = fixture::unhex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b31"
        "5ececbb6406837bf51f5");
    std::ranges::copy(point, receipt.point.begin());
  };
  const auto r = submit(RASP_SK_CREATE);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
  EXPECT_EQ(state().p.state().os.stored_keys(), 1U);
  auto manifest = std::make_unique<rasp::keys::Manifest>();
  ASSERT_TRUE(rasp::keys::decode_manifest(state().p.state().os.state().disk, *manifest));
  EXPECT_EQ(manifest->records[0].info.public_key_x963[0], 0U);
}

TEST_F(AdapterSeams, r5_whenWitnessWriteFailsBeforePublication_retainsUnknownReservationWithoutRollback) {
  witness_failure(false);
}
TEST_F(AdapterSeams, r5_whenWitnessWritePublishesBeforeError_recoveryUsesOnlyItsDurableWitness) {
  witness_failure(true);
}

TEST_F(AdapterSeams, r2_whenRefusalHashBindingIsChanged_ignoresItUntilExactOriginalAck) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  fixture::publish(7);
  state().p.start_prompt();
  auto original = std::make_unique<rasp::keys::PromptCheck>(state().p.prompt());
  auto& hash_digit = state().p.prompt().snapshot.gate_request.expected_policy_sha256[0];
  hash_digit = hash_digit == '0' ? '1' : '0';
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->take_state, RASP_SK_PENDING);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
  rasp::keys::authenticated(state().p.state().auth_job, original->operation_status, no_diagnostic(), original.get());
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  EXPECT_EQ(std::memcmp(&state().result->completion.gate, &original->gate, sizeof(original->gate)), 0);
}
TEST_F(AdapterSeams, r2_whenStaleQueryPinsNativeEntry_closeAndDistinctReattachmentWaitForIt) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.start_prompt();
  const auto retired = state().p.state().auth_job;
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  auto output = std::make_unique<rasp::keys::PromptCheck>();
  std::promise<void> entered;
  std::promise<void> release;
  const auto released = release.get_future().share();
  std::atomic<bool> paused{false};
  state().p.state().os.state().during_clock = [&] {
    if (!paused.exchange(true)) {
      entered.set_value();
      released.wait();
    }
  };
  auto query = std::async(std::launch::async, [&] { return rasp::keys::prompt_eligibility(retired, *output); });
  entered.get_future().wait();
  RaspScopedKeyControlV1 c{};
  c.abi_version = 1;
  c.struct_size = sizeof(c);
  c.client = state().opened.client;
  c.action = RASP_SK_CLOSE_CLIENT;
  RaspScopedKeyControlResultV1 out{};
  EXPECT_EQ(rasp_scoped_key_control_v1(&c, sizeof(c), &out, sizeof(out)), RASP_SK_CALL_OK);
  auto closing = std::async(std::launch::async, [&] { return state().p.state().os.step(); });
  EXPECT_EQ(closing.wait_for(std::chrono::milliseconds(20)), std::future_status::timeout);
  EXPECT_TRUE(state().p.state().os.state().storage_owned);
  EXPECT_FALSE(rasp::keys::detach_platform(state().p));
  release.set_value();
  EXPECT_EQ(query.get(), RASP_SK_OP_NOT_FOUND);
  EXPECT_TRUE(closing.get());
  state().p.state().os.state().during_clock = {};
  EXPECT_FALSE(state().p.state().os.state().storage_owned);
  ASSERT_TRUE(rasp::keys::detach_platform(state().p));
  fixture::Provider replacement;
  ASSERT_TRUE(rasp::keys::attach_platform(replacement));
  const auto old_calls = state().p.state().os.state().calls.load();
  EXPECT_EQ(rasp::keys::prompt_eligibility(retired, *output), RASP_SK_OP_NOT_FOUND);
  rasp::keys::authenticated(retired, RASP_SK_OP_OK);
  rasp::keys::run_job(retired);
  EXPECT_EQ(state().p.state().os.state().calls.load(), old_calls);
  EXPECT_EQ(replacement.state().generates.load(), 0U);
  EXPECT_EQ(replacement.state().prompts.load(), 0U);
  EXPECT_EQ(replacement.state().signs.load(), 0U);
  EXPECT_EQ(replacement.state().erases.load(), 0U);
  EXPECT_EQ(replacement.state().persists.load(), 0U);
  EXPECT_TRUE(rasp::keys::detach_platform(replacement));
  EXPECT_TRUE(rasp::keys::attach_platform(state().p));
}

TEST_F(AdapterSeams, r2_whenPromptLaunchFails_afterQueryPermit_doesNotFabricateAuthSuccess) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  state().p.state().os.state().auth_status = RASP_SK_OP_AUTH_UNAVAILABLE;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  state().p.start_prompt();
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_OK);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_AUTH_UNAVAILABLE);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
}
TEST_F(AdapterSeams, r2_whenExpectedPolicyHashDoesNotMatch_refusesBeforeAnyPromptOrPrimitive) {
  close();
  state().spec = fixture::config(true);
  state().spec.namespaces[0].expected_policy_sha256[0] ^= std::uint8_t{1};
  state().p.state().os.state().disk.clear();
  open();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
  EXPECT_EQ(state().result->completion.gate_present, 1U);
}
TEST_F(AdapterSeams, r2_whenClockRegressesBeforeQueuedPrompt_latchesRefusalWithoutUi) {
  biometry();
  const auto k = key();
  state().p.state().delayed_prompt = true;
  const auto r = submit(RASP_SK_SIGN, k.key_handle);
  ASSERT_TRUE(state().p.state().os.step());
  fixture::ticks().fetch_sub(1);
  state().p.start_prompt();
  EXPECT_EQ(state().p.state().query_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
  state().p.acknowledge(RASP_SK_OP_OK);
  state().p.state().os.drain();
  take(r);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
  EXPECT_EQ(state().p.state().os.state().prompts.load(), 0U);
  EXPECT_EQ(state().p.state().primitive_calls, 0U);
}

}  // namespace
