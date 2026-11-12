/// Real public companion operations, actual HD02 gate and controlled owned adapter interleavings.
#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <future>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <span>
#include <thread>
#include <vector>

#include "encoding.h"
#include "entry.h"
#include "platform.h"
#include "rasp/local_policy_host.h"
#include "rasp/scoped_key.h"
#include "support.h"

namespace {
/// Plain test-owned inputs/results and controllable provider; not SDK-owned storage.
struct FixtureState {
  fixture::Provider provider;
  RaspScopedKeyClientSpecV1 spec{};
  RaspScopedKeyClientOpenedV1 client{};
  std::unique_ptr<RaspScopedKeySubmitV1> input = std::make_unique<RaspScopedKeySubmitV1>();
  std::unique_ptr<RaspScopedKeyTakeResultV1> result = std::make_unique<RaspScopedKeyTakeResultV1>();
  std::vector<RaspScopedKeyTokenV1> deliveries;
};
/// Public calls only; fixture provider replaces OS boundaries, not the shared state machine.
class ScopedKeys : public ::testing::Test {
 private:
  FixtureState state_{};

 protected:
  [[nodiscard]] FixtureState& state() { return state_; }
  [[nodiscard]] const FixtureState& state() const { return state_; }
  /// Attach only a test-owned provider and publish actual typed benign evidence.
  void SetUp() override {
    fixture::ticks().fetch_add(1000000);
    fixture::publish();
    fixture::publish();
    ASSERT_TRUE(rasp::keys::attach_platform(state().provider));
    state().spec = fixture::config();
    open();
  }
  /// Release every outstanding controlled OS callback before destroying the provider.
  void TearDown() override {
    for (const auto& request : state().deliveries) {
      rasp::keys::end_delivery(request);
    }
    for (const auto& job : state().provider.state().auth_jobs) {
      rasp::keys::authenticated(job, RASP_SK_OP_CANCELLED);
    }
    static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
    state().provider.state().close_fail = false;
    state().provider.state().random_fail = false;
    state().provider.state().schedule_fail = false;
    state().provider.drain();
    for (const auto& job : state().provider.state().auth_jobs) {
      rasp::keys::authenticated(job, RASP_SK_OP_CANCELLED);
    }
    state().provider.drain();
    EXPECT_TRUE(rasp::keys::detach_platform(state().provider));
  }
  /// Open with the actual primitive C ABI on its host-worker fixture thread.
  void open() {
    ASSERT_EQ(
        rasp_scoped_key_client_open_v1(&state().spec, sizeof(state().spec), &state().client, sizeof(state().client)),
        RASP_SK_CALL_OK);
    ASSERT_EQ(state().client.operation_status, RASP_SK_OP_OK);
  }
  /// Prepare a heap-owned request and every mandatory signed-message field.
  void request(RaspScopedKeyOperationV1 operation, std::size_t space = 0) {
    std::memset(state().input.get(), 0, sizeof(*state().input));
    state().input->abi_version = 1;
    state().input->struct_size = sizeof(*state().input);
    state().input->client = state().client.client;
    state().input->namespace_handle = std::span(state().client.namespaces)[space].namespace_handle;
    state().input->operation = operation;
    state().input->request_ttl_ms = 60000;
    if (operation == RASP_SK_SIGN) {
      auto& sign = state().input->input.sign;
      sign.expected_purpose_length = 19;
      std::memcpy(std::span(sign.expected_purpose).data(), "transaction_receipt", 19);
      sign.audience_length = 16;
      std::memcpy(std::span(sign.audience).data(), "receipts.example", 16);
      sign.transaction_id[0] = 1;
      sign.challenge[0] = 2;
      sign.transaction_length = 4;
      std::memcpy(std::span(sign.transaction).data(), "data", 4);
      sign.interaction = RASP_SK_ALLOW_SYSTEM_BIOMETRY;
    }
  }
  /// Return admission without replacing any part of the shared facade.
  RaspScopedKeyAdmissionV1 admit() {
    RaspScopedKeyAdmissionV1 output{};
    EXPECT_EQ(rasp_scoped_key_submit_v1(state().input.get(), sizeof(*state().input), &output, sizeof(output)),
              RASP_SK_CALL_OK);
    return output;
  }
  /// Nonblocking owned take; tests decide when provider work is allowed to progress.
  void take(const RaspScopedKeyTokenV1& token) {
    RaspScopedKeyTakeRequestV1 value{};
    value.abi_version = 1;
    value.struct_size = sizeof(value);
    value.client = state().client.client;
    value.request = token;
    ASSERT_EQ(rasp_scoped_key_take_v1(&value, sizeof(value), state().result.get(), sizeof(*state().result)),
              RASP_SK_CALL_OK);
  }
  /// Pending/unknown results cannot retain a prior owned completion or diagnostic projection.
  void empty_completion() const {
    EXPECT_TRUE(std::ranges::all_of(std::as_bytes(std::span(&state().result->completion, 1)),
                                    [](std::byte byte) { return byte == std::byte{}; }));
  }
  /// Bounded control result is independent of operation/erasure success.
  [[nodiscard]] RaspScopedKeyControlResultV1 control(std::uint32_t action, RaspScopedKeyTokenV1 target = {}) const {
    RaspScopedKeyControlV1 value{};
    value.abi_version = 1;
    value.struct_size = sizeof(value);
    value.client = state().client.client;
    value.action = action;
    value.target = target;
    RaspScopedKeyControlResultV1 output{};
    const auto status = rasp_scoped_key_control_v1(&value, sizeof(value), &output, sizeof(output));
    EXPECT_TRUE(status == RASP_SK_CALL_OK || status == RASP_SK_CALL_BUSY);
    return output;
  }
  /// Actual fixture-owned key generation through the shipping C facade.
  RaspScopedKeyValueKeyV1 create(std::size_t space = 0) {
    request(RASP_SK_CREATE, space);
    const auto admission = admit();
    EXPECT_EQ(admission.admission_state, RASP_SK_ACCEPTED);
    state().provider.drain();
    take(admission.request);
    EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
    return state().result->completion.value.key;
  }
  /// Close before changing immutable namespace profile.
  void reopen(bool bio = false, std::uint32_t spaces = 1) {
    static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
    state().provider.drain();
    state().spec = fixture::config(bio, spaces);
    open();
  }
};
TEST_F(ScopedKeys, sign_whenOwnedKeyAndRealGateAllow_returnsIndependentlyVerifiedSignature) {
  const auto key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto independent = fixture::message(key.info, state().spec, state().input->input.sign);
  const auto admission = admit();
  std::memset(state().input.get(), 0xa5, sizeof(*state().input));
  state().provider.drain();
  take(admission.request);
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  ASSERT_EQ(state().result->completion.value_tag, RASP_SK_VALUE_SIGNATURE);
  EXPECT_EQ(state().provider.state().last_message, independent);
  EXPECT_TRUE(fixture::verify(key.info, independent, state().result->completion.value.signature));
  auto changed = independent;
  changed.back() ^= std::uint8_t{1};
  EXPECT_FALSE(fixture::verify(key.info, changed, state().result->completion.value.signature));
  EXPECT_EQ(state().result->completion.gate.action, RASP_LOCAL_ALLOW);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
}
TEST_F(ScopedKeys, authentication_whenAdapterReturnsNotReady_completesFailureWithoutReposting) {
  reopen(true);
  const auto key = create();
  state().provider.state().auth_status = RASP_SK_OP_NOT_READY;
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto admission = admit();
  ASSERT_TRUE(state().provider.step());
  EXPECT_TRUE(state().provider.state().queue.empty());
  EXPECT_EQ(state().provider.state().prompts, 1U);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_NOT_READY);
  state().provider.state().auth_status = RASP_SK_OP_OK;
}
TEST_F(ScopedKeys, storage_whenTombstonePublishedBeforeError_latchesUntilReopenWithoutOverwritingIt) {
  reopen(false, 2);
  const auto key = create();
  state().provider.state().publish_before_error = true;
  state().provider.state().persist_fail_at = static_cast<int>(state().provider.state().persists.load() + 1);
  request(RASP_SK_DELETE);
  state().input->input.key_id = key.info.key_id;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.durability, RASP_SK_DURABILITY_UNKNOWN);
  const auto uncertain_disk = state().provider.state().disk;
  request(RASP_SK_CREATE, 1);
  EXPECT_EQ(admit().admission_state, RASP_SK_REJECTED);
  state().provider.drain();
  static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
  state().provider.drain();
  EXPECT_EQ(state().provider.state().disk, uncertain_disk);
  open();
  EXPECT_EQ(state().provider.state().erases, 1U);
  request(RASP_SK_REOPEN);
  state().input->input.key_id = key.info.key_id;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_NOT_FOUND);
}
TEST_F(ScopedKeys, authentication_whenCallbackPrecedesWorkerYield_resumesExactJobOnce) {
  reopen(true);
  const auto key = create();
  state().provider.state().immediate_auth = true;
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().provider.state().signs, 1U);
  EXPECT_EQ(state().provider.state().prompts, 1U);
  ASSERT_EQ(state().provider.state().auth_jobs.size(), 1U);
  rasp::keys::authenticated(state().provider.state().auth_jobs.front(), RASP_SK_OP_OK);
  state().provider.drain();
  EXPECT_EQ(state().provider.state().signs, 1U);
}
TEST_F(ScopedKeys, delivery_whenReleaseContends_neverLosesTheBoundedCallbackLease) {
  const auto key = create();
  for (std::size_t index = 0; index < 8; ++index) {
    request(RASP_SK_DESCRIBE);
    state().input->input.key_handle = key.key_handle;
    const auto admission = admit();
    state().provider.drain();
    ASSERT_TRUE(rasp::keys::begin_delivery(admission.request));
    state().deliveries.push_back(admission.request);
    take(admission.request);
  }
  std::atomic<bool> stop{false};
  std::atomic<std::size_t> contention{0};
  const auto contender = [&] {
    RaspScopedKeyControlV1 value{};
    value.abi_version = 1;
    value.struct_size = sizeof(value);
    value.client = state().client.client;
    value.action = RASP_SK_CANCEL;
    value.target.bytes[0] = 0xfe;
    RaspScopedKeyControlResultV1 output{};
    while (!stop.load()) {
      if (rasp_scoped_key_control_v1(&value, sizeof(value), &output, sizeof(output)) == RASP_SK_CALL_BUSY) {
        contention.fetch_add(1);
      }
    }
  };
  std::thread first(contender);
  std::thread second(contender);
  while (contention.load() < 20) {
    std::this_thread::yield();
  }
  for (const auto& token : state().deliveries) {
    rasp::keys::end_delivery(token);
  }
  stop.store(true);
  first.join();
  second.join();
  auto closed = control(RASP_SK_CLOSE_CLIENT);
  state().provider.drain();
  closed = control(RASP_SK_CLOSE_CLIENT);
  EXPECT_EQ(closed.outcome, RASP_SK_ALREADY_CLOSED);
}
TEST_F(ScopedKeys, authentication_whenLaterCancelledDuplicateCallback_cannotResumeSigning) {
  reopen(true);
  const auto key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto admission = admit();
  state().provider.drain();
  ASSERT_EQ(state().provider.state().auth_jobs.size(), 1U);
  static_cast<void>(control(RASP_SK_CANCEL, admission.request));
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
  rasp::keys::authenticated(state().provider.state().auth_jobs.front(), RASP_SK_OP_OK);
  state().provider.drain();
  EXPECT_EQ(state().provider.state().signs, 0U);
  rasp::keys::authenticated(state().provider.state().auth_jobs.front(), RASP_SK_OP_OK);
  state().provider.drain();
  EXPECT_EQ(state().provider.state().signs, 0U);
}
TEST_F(ScopedKeys, gate_whenActualPredicateIsUnavailableOrPresent_neverCallsSigning) {
  const auto key = create();
  for (const bool unavailable : {false, true}) {
    fixture::publish(unavailable ? 0 : 42, unavailable);
    request(RASP_SK_SIGN);
    state().input->input.sign.key = key.key_handle;
    const auto admission = admit();
    state().provider.drain();
    take(admission.request);
    EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
    EXPECT_EQ(state().result->completion.gate.action, RASP_LOCAL_DENY);
    EXPECT_EQ(state().provider.state().signs, 0U);
  }
}
TEST_F(ScopedKeys, gate_whenItChangesDuringAuthentication_rechecksBeforePrimitive) {
  reopen(true);
  const auto key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto admission = admit();
  state().provider.drain();
  fixture::publish(42);
  rasp::keys::authenticated(state().provider.state().auth_jobs.front(), RASP_SK_OP_OK);
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  EXPECT_EQ(state().provider.state().signs, 0U);
}
TEST_F(ScopedKeys, gate_whenItChangesAfterPrimitive_withholdsSignatureAtTake) {
  const auto key = create();
  state().provider.state().during_sign = [] { fixture::publish(42); };
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().provider.state().signs, 1U);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_GATE_REJECTED);
  EXPECT_EQ(state().result->completion.value_tag, RASP_SK_VALUE_NONE);
}
TEST_F(ScopedKeys, create_whenCancelledInsidePhysicalGeneration_cleansOnlyItsDurableReservation) {
  request(RASP_SK_CREATE);
  const auto admission = admit();
  state().provider.state().during_create = [&] { static_cast<void>(control(RASP_SK_CANCEL, admission.request)); };
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
  EXPECT_EQ(state().provider.state().generates, 1U);
  EXPECT_EQ(state().provider.state().erases, 1U);
  EXPECT_EQ(state().result->completion.effect, RASP_SK_KEY_ABSENT);
}
TEST_F(ScopedKeys, erase_whenTombstoneWriteFails_reportsUnknownAndPerformsNoDeletion) {
  const auto key = create();
  const auto before = state().provider.state().erases.load();
  state().provider.state().persist_fail_at = static_cast<int>(state().provider.state().persists + 1);
  request(RASP_SK_DELETE);
  state().input->input.key_id = key.info.key_id;
  const auto admission = admit();
  EXPECT_EQ(admission.durability, RASP_SK_IN_MEMORY_ONLY);
  state().provider.drain();
  take(admission.request);
  EXPECT_NE(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().result->completion.durability, RASP_SK_DURABILITY_UNKNOWN);
  EXPECT_EQ(state().provider.state().erases, before);
}
TEST_F(ScopedKeys, storage_whenRestoredWithoutItsKey_neverRegenerates) {
  const auto key = create();
  rasp::keys::KeyReference reference{};
  reference.key_id = key.info.key_id;
  ASSERT_EQ(state().provider.erase(reference), RASP_SK_OP_OK);
  request(RASP_SK_REOPEN);
  state().input->input.key_id = key.info.key_id;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_NOT_FOUND);
  EXPECT_EQ(state().provider.state().generates, 1U);
}
TEST_F(ScopedKeys, queues_whenEightOwnedRequestsRetained_rejectsNinthWithoutAllocation) {
  const auto key = create();
  for (std::size_t index = 0; index < 8; ++index) {
    request(RASP_SK_DESCRIBE);
    state().input->input.key_handle = key.key_handle;
    EXPECT_EQ(admit().admission_state, RASP_SK_ACCEPTED);
  }
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_RESOURCE_EXHAUSTED);
  EXPECT_LE(state().provider.state().max_queue, 2U);
}
TEST_F(ScopedKeys, lifetime_whenDeadlineIsExactBoundaryOrNextNanosecond_expiresWithoutSigning) {
  const auto key = create();
  for (const auto delta : {UINT64_C(1000000), UINT64_C(1000001)}) {
    request(RASP_SK_SIGN);
    state().input->input.sign.key = key.key_handle;
    state().input->request_ttl_ms = 1;
    const auto admission = admit();
    fixture::ticks().fetch_add(delta);
    state().provider.drain();
    take(admission.request);
    EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_EXPIRED);
    EXPECT_EQ(state().provider.state().signs, 0U);
  }
}
TEST_F(ScopedKeys, lifetime_whenLeaseReaches300SecondsOrNextNanosecond_rejectsHandle) {
  const auto key = create();
  fixture::ticks().fetch_add(UINT64_C(300000000000));
  fixture::publish();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_EXPIRED);
  fixture::ticks().fetch_add(1);
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_EXPIRED);
}
TEST_F(ScopedKeys, handles_whenSixteenLeasesExist_rejectsSeventeenthBeforeProviderWork) {
  const auto key = create();
  for (std::size_t index = 1; index < 16; ++index) {
    request(RASP_SK_REOPEN);
    state().input->input.key_id = key.info.key_id;
    const auto admission = admit();
    ASSERT_EQ(admission.admission_state, RASP_SK_ACCEPTED);
    state().provider.drain();
    take(admission.request);
    ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  }
  request(RASP_SK_REOPEN);
  state().input->input.key_id = key.info.key_id;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_RESOURCE_EXHAUSTED);
  EXPECT_EQ(state().provider.state().generates, 1U);
}
TEST_F(ScopedKeys, provider_whenTwoPhysicalSignsHang_closeRetainsExclusiveOwnerAndAllSlots) {
  const auto first_key = create();
  const auto second_key = create();
  std::atomic<std::size_t> entered{0};
  std::atomic<bool> release{false};
  std::promise<void> first_entered;
  std::promise<void> second_entered;
  const auto first_signal = first_entered.get_future();
  const auto second_signal = second_entered.get_future();
  state().provider.state().during_sign = [&] {
    const auto order = entered.fetch_add(1);
    if (order == 0) {
      first_entered.set_value();
    } else if (order == 1) {
      second_entered.set_value();
    }
    while (!release.load()) {
      std::this_thread::yield();
    }
  };
  request(RASP_SK_SIGN);
  state().input->input.sign.key = first_key.key_handle;
  const auto first_request = admit();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = second_key.key_handle;
  const auto second_request = admit();
  static_cast<void>(first_request);
  static_cast<void>(second_request);
  std::thread first([&] { state().provider.step(); });
  const auto first_status = first_signal.wait_for(std::chrono::seconds(2));
  std::thread second([&] { state().provider.step(); });
  const auto second_status = second_signal.wait_for(std::chrono::seconds(2));
  if (first_status != std::future_status::ready || second_status != std::future_status::ready) {
    release.store(true);
    first.join();
    second.join();
    FAIL() << "fixture could not enter both physical primitives";
  }
  const auto closing = control(RASP_SK_CLOSE_CLIENT);
  EXPECT_EQ(closing.outcome, RASP_SK_DRAINING);
  EXPECT_EQ(closing.retained_jobs, 2U);
  RaspScopedKeyClientOpenedV1 replacement{};
  EXPECT_EQ(rasp_scoped_key_client_open_v1(&state().spec, sizeof(state().spec), &replacement, sizeof(replacement)),
            RASP_SK_CALL_CLOSING);
  EXPECT_TRUE(state().provider.state().storage_owned);
  release.store(true);
  first.join();
  second.join();
  state().provider.drain();
  EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).outcome, RASP_SK_ALREADY_CLOSED);
  EXPECT_LE(state().provider.state().max_queue, 2U);
}
TEST_F(ScopedKeys, authentication_whenTwoKeysWait_allowsOnlyOnePromptAndTwoReservedJobs) {
  reopen(true);
  const auto first = create();
  const auto second = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = first.key_handle;
  const auto a = admit();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = second.key_handle;
  const auto b = admit();
  state().provider.drain();
  ASSERT_EQ(state().provider.state().prompts, 1U);
  rasp::keys::authenticated(state().provider.state().auth_jobs.front(), RASP_SK_OP_OK);
  state().provider.drain();
  ASSERT_EQ(state().provider.state().prompts, 2U);
  ASSERT_EQ(state().provider.state().auth_jobs.size(), 2U);
  rasp::keys::authenticated(state().provider.state().auth_jobs.back(), RASP_SK_OP_OK);
  state().provider.drain();
  take(a.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  take(b.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
}
TEST_F(ScopedKeys, metadata_whenGateDenies_stillCreatesAndDeletesWithoutAuthentication) {
  fixture::publish(42);
  const auto key = create();
  EXPECT_EQ(state().provider.state().prompts, 0U);
  request(RASP_SK_DELETE);
  state().input->input.key_id = key.info.key_id;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().result->completion.gate_present, 0U);
  EXPECT_EQ(state().result->completion.durability, RASP_SK_DELETION_CONFIRMED);
}
TEST_F(ScopedKeys, reset_whenOtherNamespaceHasKeys_deletesOnlyOriginalOwnedTargets) {
  reopen(false, 2);
  const auto first = create(0);
  const auto second = create(1);
  request(RASP_SK_RESET_NAMESPACE, 0);
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().provider.state().deleted.size(), 1U);
  EXPECT_EQ(state().provider.state().deleted.front(), fixture::identity(first.info.key_id));
  request(RASP_SK_DESCRIBE, 1);
  state().input->input.key_handle = second.key_handle;
  const auto retained = admit();
  state().provider.drain();
  take(retained.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
}
TEST_F(ScopedKeys, cleanup_whenPhysicalDeletionFails_keepsDurableScopeForReopenRetry) {
  const auto key = create();
  state().provider.state().erase_fail = true;
  request(RASP_SK_DELETE);
  state().input->input.key_id = key.info.key_id;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
  EXPECT_EQ(state().result->completion.durability, RASP_SK_TOMBSTONES_DURABLE);
  state().provider.state().erase_fail = false;
  static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
  state().provider.drain();
  open();
  EXPECT_EQ(state().provider.state().deleted.back(), fixture::identity(key.info.key_id));
  request(RASP_SK_REOPEN);
  state().input->input.key_id = key.info.key_id;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_NOT_FOUND);
}
TEST_F(ScopedKeys, random_whenGenerationEntropyFails_createsNoKeyOrSuccess) {
  state().provider.state().random_fail = true;
  request(RASP_SK_CREATE);
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_INTERNAL_ERROR);
  EXPECT_EQ(state().provider.state().generates, 0U);
}
TEST_F(ScopedKeys, clock_whenSampleFails_latchesUntilClientReopenedAndNeverSigns) {
  const auto key = create();
  state().provider.state().clock_fail = true;
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
  state().provider.state().clock_fail = false;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
  EXPECT_EQ(state().provider.state().signs, 0U);
}
TEST_F(ScopedKeys, abi_whenUnalignedOverlapUnknownOrWrongSize_neverWritesOutsideCallerRange) {
  request(RASP_SK_CREATE);
  RaspScopedKeyAdmissionV1 output{};
  EXPECT_EQ(rasp_scoped_key_submit_v1(state().input.get(), sizeof(*state().input) - 1, &output, sizeof(output)),
            RASP_SK_CALL_INVALID_ARGUMENT);
  EXPECT_EQ(rasp_scoped_key_submit_v1(state().input.get(), sizeof(*state().input), &output, sizeof(output) - 1),
            RASP_SK_CALL_INVALID_ARGUMENT);
  EXPECT_EQ(
      rasp_scoped_key_submit_v1(
          state().input.get(), sizeof(*state().input),
          std::bit_cast<RaspScopedKeyAdmissionV1*>(std::bit_cast<std::uintptr_t>(state().input.get())), sizeof(output)),
      RASP_SK_CALL_INVALID_ARGUMENT);
  const auto* unaligned =
      std::bit_cast<const RaspScopedKeySubmitV1*>(std::bit_cast<std::uintptr_t>(state().input.get()) + 1U);
  EXPECT_EQ(rasp_scoped_key_submit_v1(unaligned, sizeof(*state().input), &output, sizeof(output)),
            RASP_SK_CALL_INVALID_ARGUMENT);
  state().input->abi_version = 2;
  EXPECT_EQ(rasp_scoped_key_submit_v1(state().input.get(), sizeof(*state().input), &output, sizeof(output)),
            RASP_SK_CALL_UNSUPPORTED_ABI);
  state().input->abi_version = 1;
  state().input->input.raw[4335] = 1;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_INVALID_ARGUMENT);
  EXPECT_EQ(state().provider.state().generates, 0U);
}
TEST_F(ScopedKeys, auth_whenUiForbidden_returnsAuthRequiredWithoutPromptOrSignature) {
  reopen(true);
  const auto key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  state().input->input.sign.interaction = RASP_SK_FORBID;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_AUTH_REQUIRED);
  EXPECT_EQ(state().provider.state().prompts, 0U);
  EXPECT_EQ(state().provider.state().signs, 0U);
}
TEST_F(ScopedKeys, purpose_whenCallerChangesPurpose_rejectsBeforeAnyKeyUse) {
  const auto key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  state().input->input.sign.expected_purpose[0] = 'x';
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_WRONG_PURPOSE);
  EXPECT_EQ(state().provider.state().signs, 0U);
}
TEST_F(ScopedKeys, detach_whenEntirePublicEntryIsPaused_cannotReplaceItsPlatformOrMutex) {
  static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
  state().provider.drain();
  std::atomic<bool> entered{false};
  std::atomic<bool> resume{false};
  state().provider.state().during_main = [&] {
    entered.store(true);
    while (!resume.load()) {
      std::this_thread::yield();
    }
  };
  RaspScopedKeyClientOpenedV1 opened{};
  std::int32_t status = -1;
  std::thread caller(
      [&] { status = rasp_scoped_key_client_open_v1(&state().spec, sizeof(state().spec), &opened, sizeof(opened)); });
  while (!entered.load()) {
    std::this_thread::yield();
  }
  const bool detached = rasp::keys::detach_platform(state().provider);
  EXPECT_FALSE(detached);
  if (detached) {
    EXPECT_TRUE(rasp::keys::attach_platform(state().provider));
  }
  resume.store(true);
  caller.join();
  state().provider.state().during_main = {};
  EXPECT_EQ(status, RASP_SK_CALL_OK);
  state().client = opened;
}
TEST_F(ScopedKeys, detach_whenStalePrivateEntriesRaceReattachment_neverAccessesAnOldProvider) {
  reopen(true);
  const auto old_key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = old_key.key_handle;
  const auto old_request = admit();
  state().provider.drain();
  ASSERT_EQ(state().provider.state().auth_jobs.size(), 1U);
  const auto old_job = state().provider.state().auth_jobs.front();
  static_cast<void>(control(RASP_SK_CANCEL, old_request.request));
  rasp::keys::authenticated(old_job, RASP_SK_OP_CANCELLED);
  state().provider.drain();
  ASSERT_TRUE(rasp::keys::begin_delivery(old_request.request));
  take(old_request.request);
  rasp::keys::end_delivery(old_request.request);
  static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
  state().provider.drain();
  const auto old_calls = state().provider.state().calls.load();
  std::atomic<bool> stop{false};
  std::thread callbacks([&] {
    while (!stop.load()) {
      rasp::keys::run_job(old_job);
      rasp::keys::authenticated(old_job, RASP_SK_OP_OK);
      static_cast<void>(rasp::keys::begin_delivery(old_request.request));
      rasp::keys::end_delivery(old_request.request);
    }
  });
  bool detached = false;
  for (std::size_t attempt = 0; attempt < 5000 && !detached; ++attempt) {
    detached = rasp::keys::detach_platform(state().provider);
  }
  fixture::Provider replacement;
  bool attached = false;
  for (std::size_t attempt = 0; attempt < 5000 && detached && !attached; ++attempt) {
    attached = rasp::keys::attach_platform(replacement);
  }
  stop.store(true);
  callbacks.join();
  ASSERT_TRUE(detached);
  ASSERT_TRUE(attached);
  open();
  request(RASP_SK_CREATE);
  const auto created = admit();
  replacement.drain();
  take(created.request);
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  const auto new_key = state().result->completion.value.key;
  request(RASP_SK_CREATE);
  const auto another = admit();
  replacement.drain();
  take(another.request);
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  const auto other_key = state().result->completion.value.key;
  request(RASP_SK_SIGN);
  state().input->input.sign.key = new_key.key_handle;
  const auto current_auth = admit();
  replacement.drain();
  ASSERT_EQ(replacement.state().auth_jobs.size(), 1U);
  request(RASP_SK_DESCRIBE);
  state().input->input.key_handle = other_key.key_handle;
  const auto current_delivery = admit();
  replacement.drain();
  ASSERT_TRUE(rasp::keys::begin_delivery(current_delivery.request));
  take(current_delivery.request);
  const auto new_calls = replacement.state().calls.load();
  for (std::size_t attempt = 0; attempt < 100; ++attempt) {
    rasp::keys::run_job(old_job);
    rasp::keys::authenticated(old_job, RASP_SK_OP_OK);
    EXPECT_FALSE(rasp::keys::begin_delivery(old_request.request));
    rasp::keys::end_delivery(old_request.request);
  }
  EXPECT_EQ(state().provider.state().calls.load(), old_calls);
  EXPECT_EQ(replacement.state().calls.load(), new_calls);
  EXPECT_EQ(replacement.state().signs.load(), 0U);
  EXPECT_EQ(replacement.state().generates.load(), 2U);
  EXPECT_EQ(replacement.state().prompts.load(), 1U);
  take(current_auth.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_PENDING);
  const auto closing = control(RASP_SK_CLOSE_CLIENT);
  EXPECT_EQ(closing.retained_callbacks, 1U);
  rasp::keys::end_delivery(current_delivery.request);
  rasp::keys::authenticated(replacement.state().auth_jobs.front(), RASP_SK_OP_CANCELLED);
  replacement.drain();
  EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).outcome, RASP_SK_ALREADY_CLOSED);
  EXPECT_EQ(replacement.state().signs.load(), 0U);
  EXPECT_EQ(state().provider.state().calls.load(), old_calls);
  ASSERT_TRUE(rasp::keys::detach_platform(replacement));
  ASSERT_TRUE(rasp::keys::attach_platform(state().provider));
}

TEST_F(ScopedKeys, deletion_whenSlotIsReusedBeforeQueuedRetry_neverWidensToTheNewKey) {
  reopen(false, 2);
  const auto original = create(0);
  request(RASP_SK_DELETE, 0);
  state().input->input.key_id = original.info.key_id;
  const auto first = admit();
  request(RASP_SK_CREATE, 1);
  const auto replacement = admit();
  request(RASP_SK_DELETE, 0);
  state().input->input.key_id = original.info.key_id;
  const auto retry = admit();
  state().provider.drain();
  take(first.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  take(replacement.request);
  ASSERT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  const auto retained = state().result->completion.value.key;
  take(retry.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  request(RASP_SK_DESCRIBE, 1);
  state().input->input.key_handle = retained.key_handle;
  const auto read = admit();
  EXPECT_EQ(read.admission_state, RASP_SK_ACCEPTED);
  state().provider.drain();
  take(read.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_TRUE(std::ranges::all_of(state().provider.state().deleted,
                                  [&](const auto& value) { return value == fixture::identity(original.info.key_id); }));
}
TEST_F(ScopedKeys, cleanup_whenDeletionFails_preservesExactDiagnosticCountsOnFailure) {
  const auto key = create();
  state().provider.state().erase_fail = true;
  request(RASP_SK_DELETE);
  state().input->input.key_id = key.info.key_id;
  const auto admission = admit();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
  EXPECT_EQ(state().result->completion.value_tag, RASP_SK_VALUE_DELETION);
  EXPECT_EQ(state().result->completion.value.deletion.requested, 1U);
  EXPECT_EQ(state().result->completion.value.deletion.confirmed_absent, 0U);
  EXPECT_EQ(state().result->completion.value.deletion.remaining, 1U);
}
}  // namespace

TEST_F(ScopedKeys, close_whenEntirePublicEntryStillUsesClock_defersStorageReleaseUntilEntryReturns) {
  const auto key = create();
  request(RASP_SK_DESCRIBE);
  state().input->input.key_handle = key.key_handle;
  std::atomic<bool> paused{false};
  std::atomic<bool> resume{false};
  std::atomic<bool> exited{false};
  std::atomic<bool> closed{false};
  state().provider.state().during_clock = [&] {
    paused.store(true);
    while (!resume.load()) {
      std::this_thread::yield();
    }
  };
  state().provider.state().during_close = [&] {
    EXPECT_TRUE(resume.load());
    closed.store(true);
  };
  std::thread public_entry([&] {
    RaspScopedKeyAdmissionV1 admission{};
    const auto status =
        rasp_scoped_key_submit_v1(state().input.get(), sizeof(*state().input), &admission, sizeof(admission));
    EXPECT_TRUE(status == RASP_SK_CALL_BUSY || status == RASP_SK_CALL_CLOSING || status == RASP_SK_CALL_NOT_FOUND);
    exited.store(true);
  });
  while (!paused.load()) {
    std::this_thread::yield();
  }
  EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).outcome, RASP_SK_DRAINING);
  ASSERT_EQ(state().provider.state().queue.size(), 1U);
  const auto close_job = state().provider.state().queue.front();
  state().provider.state().queue.pop_front();
  std::atomic<bool> worker_started{false};
  std::thread worker([&] {
    worker_started.store(true);
    rasp::keys::run_job(close_job);
  });
  while (!worker_started.load()) {
    std::this_thread::yield();
  }
  EXPECT_FALSE(closed.load());
  EXPECT_FALSE(exited.load());
  fixture::Provider replacement;
  EXPECT_FALSE(rasp::keys::detach_platform(state().provider));
  EXPECT_FALSE(rasp::keys::attach_platform(replacement));
  resume.store(true);
  public_entry.join();
  worker.join();
  state().provider.state().during_clock = {};
  state().provider.state().during_close = {};
  EXPECT_TRUE(exited.load());
  EXPECT_TRUE(closed.load());
  EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).outcome, RASP_SK_ALREADY_CLOSED);
}

TEST_F(ScopedKeys, provenance_whenDefaultLockIsStricter_reportsItWithoutPermittingWeakerExplicitProfile) {
  const auto key = create();
  auto info = key.info;
  auto space = state().spec.namespaces[0];
  ASSERT_TRUE(rasp::keys::valid_info(info, space));
  info.provenance.lock_observed = RASP_SK_UNLOCKED_REQUIRED;
  EXPECT_TRUE(rasp::keys::valid_info(info, space));
  space.lock_requirement = RASP_SK_UNLOCKED_REQUIRED;
  info.lock_requirement = RASP_SK_UNLOCKED_REQUIRED;
  info.provenance.lock_observed = RASP_SK_PLATFORM_DEFAULT;
  EXPECT_FALSE(rasp::keys::valid_info(info, space));
  info = key.info;
  info.provenance.security_level = RASP_SK_SECURE_ENCLAVE;
  EXPECT_FALSE(rasp::keys::valid_info(info, state().spec.namespaces[0]));
  info = key.info;
  info.provenance.source = RASP_SK_APPLE_ATTRIBUTES_AND_CREATION;
  EXPECT_FALSE(rasp::keys::valid_info(info, state().spec.namespaces[0]));
}

TEST_F(ScopedKeys, keyId_whenEntropyRepeats_rejectsCollisionAfterFourAttemptsWithoutFallback) {
  state().provider.state().constant_entropy = true;
  const auto first = create();
  const auto before = state().provider.state().random_calls.load();
  request(RASP_SK_CREATE);
  const auto collision = admit();
  state().provider.drain();
  take(collision.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_INTERNAL_ERROR);
  EXPECT_EQ(state().provider.state().random_calls.load() - before, 4U);
  EXPECT_EQ(state().provider.state().generates, 1U);
  request(RASP_SK_DESCRIBE);
  state().input->input.key_handle = first.key_handle;
  const auto unaffected = admit();
  state().provider.drain();
  take(unaffected.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
}
TEST_F(ScopedKeys, storage_whenReservationRestored_recoversOnlyItsExactKeyAndNeverRegenerates) {
  std::vector<std::uint8_t> reserved;
  state().provider.state().during_create = [&] { reserved = state().provider.state().disk; };
  const auto key = create();
  state().provider.state().during_create = {};
  ASSERT_FALSE(reserved.empty());
  static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
  state().provider.drain();
  state().provider.state().disk = reserved;
  open();
  EXPECT_EQ(state().provider.state().erases, 1U);
  ASSERT_EQ(state().provider.state().deleted.size(), 1U);
  EXPECT_EQ(state().provider.state().deleted.front(), fixture::identity(key.info.key_id));
  EXPECT_EQ(state().provider.state().generates, 1U);
  request(RASP_SK_REOPEN);
  state().input->input.key_id = key.info.key_id;
  EXPECT_EQ(admit().operation_status, RASP_SK_OP_NOT_FOUND);
}
TEST_F(ScopedKeys, storage_whenLiveManifestReopened_reusesExistingPublicKeyWithoutGeneration) {
  const auto key = create();
  static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
  state().provider.drain();
  open();
  request(RASP_SK_REOPEN);
  state().input->input.key_id = key.info.key_id;
  const auto admitted = admit();
  state().provider.drain();
  take(admitted.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_TRUE(std::ranges::equal(state().result->completion.value.key.info.public_key_x963, key.info.public_key_x963));
  EXPECT_EQ(state().provider.state().generates, 1U);
}

TEST_F(ScopedKeys, clock_whenRegressionOrLeaseOverflow_latchesAllUsesUntilReopen) {
  for (const bool overflow : {false, true}) {
    const auto key = create();
    const auto original = fixture::ticks().load();
    fixture::ticks().store(overflow ? std::numeric_limits<std::uint64_t>::max() : original - 1);
    request(RASP_SK_DESCRIBE);
    state().input->input.key_handle = key.key_handle;
    EXPECT_EQ(admit().operation_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
    fixture::ticks().store(original + 1);
    EXPECT_EQ(admit().operation_status, RASP_SK_OP_CLOCK_UNAVAILABLE);
    static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
    state().provider.drain();
    open();
  }
}

TEST_F(ScopedKeys, entry_whenRealQueuedJobArrivesDuringRegistryWriter_workerEventuallyRunsExactlyOnce) {
  request(RASP_SK_CREATE);
  const auto admission = admit();
  ASSERT_EQ(state().provider.state().queue.size(), 1U);
  const auto job = state().provider.state().queue.front();
  state().provider.state().queue.pop_front();
  std::future<void> worker;
  {
    rasp::keys::EntryLease writer;
    ASSERT_TRUE(writer.try_exclusive());
    worker = std::async(std::launch::async, [job] { rasp::keys::run_job(job); });
    EXPECT_EQ(worker.wait_for(std::chrono::milliseconds(100)), std::future_status::timeout);
    EXPECT_EQ(state().provider.state().generates, 0U);
  }
  worker.get();
  EXPECT_EQ(state().provider.state().generates, 1U);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  rasp::keys::run_job(job);
  EXPECT_EQ(state().provider.state().generates, 1U);
  fixture::Provider replacement;
  EXPECT_FALSE(rasp::keys::attach_platform(replacement));
  EXPECT_FALSE(rasp::keys::detach_platform(state().provider));
}
TEST_F(ScopedKeys, entry_whenRealAuthAckArrivesDuringRegistryWriter_workerEventuallyAcknowledgesOnce) {
  reopen(true);
  const auto key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto admission = admit();
  state().provider.drain();
  ASSERT_EQ(state().provider.state().auth_jobs.size(), 1U);
  const auto job = state().provider.state().auth_jobs.front();
  std::future<void> worker;
  {
    rasp::keys::EntryLease writer;
    ASSERT_TRUE(writer.try_exclusive());
    worker = std::async(std::launch::async, [job] { rasp::keys::authenticated(job, RASP_SK_OP_OK); });
    EXPECT_EQ(worker.wait_for(std::chrono::milliseconds(100)), std::future_status::timeout);
  }
  worker.get();
  state().provider.drain();
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().provider.state().signs, 1U);
  rasp::keys::authenticated(job, RASP_SK_OP_CANCELLED);
  rasp::keys::authenticated(job, RASP_SK_OP_OK);
  state().provider.drain();
  EXPECT_EQ(state().provider.state().signs, 1U);
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto next = admit();
  state().provider.drain();
  const auto next_job = state().provider.state().auth_jobs.back();
  fixture::Provider replacement;
  auto next_worker = std::async(std::launch::async, [next_job] { rasp::keys::authenticated(next_job, RASP_SK_OP_OK); });
  for (std::size_t attempt = 0; attempt < 64; ++attempt) {
    EXPECT_FALSE(rasp::keys::attach_platform(replacement));
  }
  next_worker.get();
  state().provider.drain();
  take(next.request);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().provider.state().signs, 2U);
}
TEST_F(ScopedKeys, entry_whenRealDeliveryAckArrivesDuringRegistryWriter_releasesWithoutBlockingUiOrAnotherAck) {
  const auto key = create();
  for (std::size_t index = 0; index < 8; ++index) {
    request(RASP_SK_DESCRIBE);
    state().input->input.key_handle = key.key_handle;
    const auto admission = admit();
    state().provider.drain();
    ASSERT_TRUE(rasp::keys::begin_delivery(admission.request));
    state().deliveries.push_back(admission.request);
    take(admission.request);
  }
  EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).retained_callbacks, 8U);
  std::future<void> ui;
  {
    rasp::keys::EntryLease writer;
    ASSERT_TRUE(writer.try_exclusive());
    ui = std::async(std::launch::async, [&] {
      for (const auto& request : state().deliveries) {
        rasp::keys::end_delivery(request);
      }
    });
    EXPECT_EQ(ui.wait_for(std::chrono::milliseconds(100)), std::future_status::ready);
    EXPECT_TRUE(state().provider.state().storage_owned);
  }
  ui.get();
  EXPECT_EQ(state().provider.state().queue.size(), 1U);
  state().provider.drain();
  EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).outcome, RASP_SK_ALREADY_CLOSED);
}
TEST_F(ScopedKeys, authentication_whenDescribeCancelsClosesOrExpiresUse_neverStartsAPrompt) {
  for (const auto scenario : {0U, 1U, 2U, 3U}) {
    reopen(true);
    const auto key = create();
    if (scenario == 3) {
      fixture::ticks().fetch_add(UINT64_C(299999000000));
      fixture::publish();
    }
    request(RASP_SK_SIGN);
    state().input->input.sign.key = key.key_handle;
    const auto admission = admit();
    const auto prompts = state().provider.state().prompts.load();
    state().provider.state().during_describe = [&] {
      if (scenario == 0) {
        static_cast<void>(control(RASP_SK_CANCEL, admission.request));
      } else if (scenario == 1) {
        static_cast<void>(control(RASP_SK_CLOSE_CLIENT));
      } else {
        fixture::ticks().fetch_add(scenario == 2 ? UINT64_C(60000000000) : UINT64_C(1000000));
        fixture::publish();
      }
    };
    state().provider.drain();
    state().provider.state().during_describe = {};
    EXPECT_EQ(state().provider.state().prompts.load(), prompts) << scenario;
    EXPECT_EQ(state().provider.state().signs.load(), 0U) << scenario;
    if (!state().provider.state().auth_jobs.empty()) {
      rasp::keys::authenticated(state().provider.state().auth_jobs.back(), RASP_SK_OP_CANCELLED);
      state().provider.drain();
    }
    if (scenario != 1) {
      take(admission.request);
      EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
      EXPECT_EQ(state().result->completion.operation_status, scenario == 0 ? RASP_SK_OP_CANCELLED : RASP_SK_OP_EXPIRED);
    } else {
      EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).outcome, RASP_SK_ALREADY_CLOSED);
    }
  }
}

TEST_F(ScopedKeys, take_whenQueuedAndCancelled_snapshotsOutstandingAndRetiredWork) {
  request(RASP_SK_CREATE);
  const auto first = admit();
  ASSERT_EQ(state().provider.state().queue.size(), 1U);
  take(first.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_PENDING);
  EXPECT_EQ(state().result->retained_requests, 1U);
  EXPECT_EQ(state().result->retained_jobs, 1U);
  empty_completion();
  const auto cancelled = control(RASP_SK_CANCEL, first.request);
  EXPECT_EQ(cancelled.retained_requests, 1U);
  EXPECT_EQ(cancelled.retained_jobs, 1U);
  EXPECT_EQ(cancelled.retained_callbacks, 0U);
  take(first.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
  EXPECT_EQ(state().result->retained_requests, 1U);
  EXPECT_EQ(state().result->retained_jobs, 1U);
  EXPECT_EQ(state().provider.state().queue.size(), 1U);
  EXPECT_EQ(state().provider.state().generates, 0U);
  take(first.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
  EXPECT_EQ(state().result->retained_requests, 1U);
  EXPECT_EQ(state().result->retained_jobs, 1U);
  empty_completion();
  state().provider.drain();
  take(first.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
  EXPECT_EQ(state().result->retained_requests, 0U);
  EXPECT_EQ(state().result->retained_jobs, 0U);
  EXPECT_EQ(state().provider.state().generates, 0U);
  request(RASP_SK_CREATE);
  const auto second = admit();
  take(first.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
  EXPECT_EQ(state().result->retained_requests, 1U);
  EXPECT_EQ(state().result->retained_jobs, 1U);
  empty_completion();
  state().provider.drain();
  take(second.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().result->retained_requests, 0U);
  EXPECT_EQ(state().result->retained_jobs, 0U);
  EXPECT_TRUE(state().provider.state().queue.empty());
  EXPECT_EQ(state().provider.state().generates, 1U);
}
TEST_F(ScopedKeys, take_whenInflightSignCancelled_countsPhysicalBorrowerUntilReturn) {
  const auto key = create();
  request(RASP_SK_SIGN);
  state().input->input.sign.key = key.key_handle;
  const auto admission = admit();
  state().provider.state().during_sign = [&] {
    const auto cancelled = control(RASP_SK_CANCEL, admission.request);
    EXPECT_EQ(cancelled.retained_requests, 1U);
    EXPECT_EQ(cancelled.retained_jobs, 1U);
    EXPECT_EQ(cancelled.retained_callbacks, 0U);
    EXPECT_TRUE(state().provider.state().queue.empty());
    take(admission.request);
    EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CANCELLED);
    EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
    EXPECT_EQ(state().result->retained_requests, 1U);
    EXPECT_EQ(state().result->retained_jobs, 1U);
    take(admission.request);
    EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
    EXPECT_EQ(state().result->retained_requests, 1U);
    EXPECT_EQ(state().result->retained_jobs, 1U);
    empty_completion();
  };
  state().provider.drain();
  state().provider.state().during_sign = {};
  EXPECT_EQ(state().provider.state().signs, 1U);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
  EXPECT_EQ(state().result->retained_requests, 0U);
  EXPECT_EQ(state().result->retained_jobs, 0U);
  empty_completion();
}
TEST_F(ScopedKeys, take_whenCallbackOwnsTransferredCompletion_countsLeaseUntilAcknowledgment) {
  const auto key = create();
  request(RASP_SK_DESCRIBE);
  state().input->input.key_handle = key.key_handle;
  const auto admission = admit();
  state().provider.drain();
  ASSERT_TRUE(rasp::keys::begin_delivery(admission.request));
  state().deliveries.push_back(admission.request);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
  EXPECT_EQ(state().result->retained_requests, 1U);
  EXPECT_EQ(state().result->retained_jobs, 0U);
  const auto counts = control(RASP_SK_CANCEL, admission.request);
  EXPECT_EQ(counts.outcome, RASP_SK_TOO_LATE);
  EXPECT_EQ(counts.retained_requests, 1U);
  EXPECT_EQ(counts.retained_jobs, 0U);
  EXPECT_EQ(counts.retained_callbacks, 1U);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
  EXPECT_EQ(state().result->retained_requests, 1U);
  EXPECT_EQ(state().result->retained_jobs, 0U);
  empty_completion();
  const auto closing = control(RASP_SK_CLOSE_CLIENT);
  EXPECT_EQ(closing.outcome, RASP_SK_DRAINING);
  EXPECT_EQ(closing.retained_callbacks, 1U);
  EXPECT_TRUE(state().provider.state().storage_owned);
  rasp::keys::end_delivery(admission.request);
  EXPECT_EQ(state().provider.state().queue.size(), 1U);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
  EXPECT_EQ(state().result->retained_requests, 0U);
  EXPECT_EQ(state().result->retained_jobs, 1U);
  empty_completion();
  const auto released = control(RASP_SK_CLOSE_CLIENT);
  EXPECT_EQ(released.retained_requests, 0U);
  EXPECT_EQ(released.retained_jobs, 1U);
  EXPECT_EQ(released.retained_callbacks, 0U);
  state().provider.drain();
  EXPECT_EQ(control(RASP_SK_CLOSE_CLIENT).outcome, RASP_SK_ALREADY_CLOSED);
}
TEST_F(ScopedKeys, take_whenTransferStartsExpiredCreateCleanup_countsDispatchedJob) {
  request(RASP_SK_CREATE);
  const auto admission = admit();
  state().provider.drain();
  ASSERT_EQ(state().provider.state().generates, 1U);
  ASSERT_TRUE(state().provider.state().queue.empty());
  fixture::ticks().fetch_add(UINT64_C(60000000000));
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_COMPLETED);
  EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_EXPIRED);
  EXPECT_EQ(state().result->retained_requests, 1U);
  EXPECT_EQ(state().result->retained_jobs, 1U);
  EXPECT_EQ(state().provider.state().queue.size(), 1U);
  EXPECT_EQ(state().provider.state().erases, 0U);
  const auto counts = control(RASP_SK_CANCEL, admission.request);
  EXPECT_EQ(counts.retained_requests, 1U);
  EXPECT_EQ(counts.retained_jobs, 1U);
  state().provider.drain();
  EXPECT_EQ(state().provider.state().erases, 1U);
  take(admission.request);
  EXPECT_EQ(state().result->take_state, RASP_SK_UNKNOWN_REQUEST);
  EXPECT_EQ(state().result->retained_requests, 0U);
  EXPECT_EQ(state().result->retained_jobs, 0U);
}
TEST_F(ScopedKeys, take_whenInvalidOrRetiredClient_doesNotDiscloseRetainedCounts) {
  const auto retired = state().client.client;
  reopen();
  request(RASP_SK_CREATE);
  const auto admission = admit();
  for (const auto& client : {retired, RaspScopedKeyTokenV1{}}) {
    RaspScopedKeyTakeRequestV1 input{};
    input.abi_version = 1;
    input.struct_size = sizeof(input);
    input.client = client;
    input.request = admission.request;
    std::memset(state().result.get(), 0xa5, sizeof(*state().result));
    EXPECT_EQ(rasp_scoped_key_take_v1(&input, sizeof(input), state().result.get(), sizeof(*state().result)),
              RASP_SK_CALL_NOT_FOUND);
    EXPECT_EQ(state().result->retained_requests, 0U);
    EXPECT_EQ(state().result->retained_jobs, 0U);
    EXPECT_EQ(state().result->take_state, RASP_SK_TAKE_NONE);
    empty_completion();
  }
  const auto counts = control(RASP_SK_CANCEL, admission.request);
  EXPECT_EQ(counts.retained_requests, 1U);
  EXPECT_EQ(counts.retained_jobs, 1U);
  EXPECT_EQ(state().provider.state().queue.size(), 1U);
  EXPECT_EQ(state().provider.state().generates, 0U);
}
namespace {
/// Failed first open has no usable client; recovery must use the actual worker-open entry.
class ScopedKeysOpenCleanup : public ::testing::Test {
 private:
  fixture::Provider provider_;
  RaspScopedKeyClientSpecV1 spec_{};
  RaspScopedKeyClientOpenedV1 opened_{};
  std::atomic<std::uint32_t> closes_{0};

 protected:
  [[nodiscard]] fixture::Provider& provider() { return provider_; }
  [[nodiscard]] std::uint32_t closes() const { return closes_.load(); }
  [[nodiscard]] const RaspScopedKeyClientOpenedV1& opened() const { return opened_; }
  void SetUp() override {
    fixture::ticks().fetch_add(1000000);
    fixture::publish();
    fixture::publish();
    spec_ = fixture::config();
    provider_.state().during_close = [this] { closes_.fetch_add(1); };
    ASSERT_TRUE(rasp::keys::attach_platform(provider_));
  }
  void TearDown() override {
    provider_.state().close_fail = false;
    provider_.state().schedule_fail = false;
    provider_.state().on_main = false;
    provider_.state().during_main = {};
    RaspScopedKeyControlV1 input{};
    input.abi_version = 1;
    input.struct_size = sizeof(input);
    input.action = RASP_SK_CLOSE_CLIENT;
    input.client = opened_.client;
    RaspScopedKeyControlResultV1 output{};
    static_cast<void>(rasp_scoped_key_control_v1(&input, sizeof(input), &output, sizeof(output)));
    provider_.drain();
    EXPECT_TRUE(rasp::keys::detach_platform(provider_));
  }
  [[nodiscard]] std::int32_t open() {
    return rasp_scoped_key_client_open_v1(&spec_, sizeof(spec_), &opened_, sizeof(opened_));
  }
  /// First close failure preserves the original operation error and never fabricates a client.
  void failed_open(std::uint32_t expected) {
    provider_.state().close_fail = true;
    ASSERT_EQ(open(), RASP_SK_CALL_OK);
    EXPECT_EQ(opened_.operation_status, expected);
    EXPECT_FALSE(rasp::keys::nonzero(opened_.client));
    EXPECT_EQ(opened_.namespace_count, 0U);
    EXPECT_EQ(closes(), 1U);
    EXPECT_TRUE(provider_.state().storage_owned);
    EXPECT_FALSE(rasp::keys::detach_platform(provider_));
  }
  /// Run exactly one bounded close attempt, then prove normal open is usable again.
  void recover(std::uint32_t expected) {
    failed_open(expected);
    ASSERT_EQ(provider_.state().queue.size(), 1U);
    const auto disk = provider_.state().disk;
    const auto persists = provider_.state().persists.load();
    provider_.state().close_fail = false;
    ASSERT_TRUE(provider_.step());
    EXPECT_EQ(closes(), 2U);
    EXPECT_TRUE(provider_.state().queue.empty());
    EXPECT_FALSE(provider_.state().storage_owned);
    EXPECT_EQ(provider_.state().disk, disk);
    EXPECT_EQ(provider_.state().persists.load(), persists);
    EXPECT_EQ(opened_.operation_status, expected);
    provider_.state().disk.clear();
    provider_.state().persist_fail_at = -1;
    ASSERT_EQ(open(), RASP_SK_CALL_OK);
    EXPECT_EQ(opened_.operation_status, RASP_SK_OP_OK);
    EXPECT_TRUE(rasp::keys::nonzero(opened_.client));
  }
};
TEST_F(ScopedKeysOpenCleanup, open_whenFirstReadIsTruncatedAndCloseFails_retriesWithoutRewritingFile) {
  provider().state().disk = {1};
  recover(RASP_SK_OP_STORAGE_CORRUPT);
}
TEST_F(ScopedKeysOpenCleanup, open_whenFirstEntropyReadAndCloseFail_retriesWithoutRewritingFile) {
  provider().state().random_fail = true;
  failed_open(RASP_SK_OP_INTERNAL_ERROR);
  provider().state().random_fail = false;
  provider().state().close_fail = false;
  ASSERT_EQ(provider().state().queue.size(), 1U);
  ASSERT_TRUE(provider().step());
  ASSERT_EQ(open(), RASP_SK_CALL_OK);
  EXPECT_EQ(opened().operation_status, RASP_SK_OP_OK);
}
TEST_F(ScopedKeysOpenCleanup, open_whenFirstPersistAndCloseFail_retriesWithoutPublishingUncertainState) {
  provider().state().persist_fail_at = 1;
  recover(RASP_SK_OP_STORAGE_UNAVAILABLE);
}
TEST_F(ScopedKeysOpenCleanup, open_whenCloseAndSchedulerKeepFailing_retriesOnlyOnExplicitWorkerEntry) {
  provider().state().persist_fail_at = 1;
  provider().state().schedule_fail = true;
  failed_open(RASP_SK_OP_STORAGE_UNAVAILABLE);
  EXPECT_TRUE(provider().state().queue.empty());
  provider().state().schedule_fail = false;
  for (std::uint32_t attempt = 0; attempt < 3; ++attempt) {
    ASSERT_EQ(open(), RASP_SK_CALL_CLOSING);
    ASSERT_EQ(provider().state().queue.size(), 1U);
    ASSERT_EQ(open(), RASP_SK_CALL_CLOSING);
    EXPECT_EQ(provider().state().queue.size(), 1U);
    ASSERT_TRUE(provider().step());
    EXPECT_EQ(closes(), attempt + 2);
    EXPECT_TRUE(provider().state().queue.empty());
    EXPECT_TRUE(provider().state().storage_owned);
    EXPECT_FALSE(rasp::keys::detach_platform(provider()));
  }
  provider().state().on_main = true;
  EXPECT_EQ(open(), RASP_SK_CALL_WRONG_THREAD);
  EXPECT_TRUE(provider().state().queue.empty());
  EXPECT_EQ(closes(), 4U);
  provider().state().on_main = false;
  provider().state().close_fail = false;
  ASSERT_EQ(open(), RASP_SK_CALL_CLOSING);
  ASSERT_EQ(provider().state().queue.size(), 1U);
  ASSERT_TRUE(provider().step());
  EXPECT_FALSE(provider().state().storage_owned);
  ASSERT_EQ(open(), RASP_SK_CALL_OK);
  EXPECT_EQ(opened().operation_status, RASP_SK_OP_OK);
  EXPECT_LE(provider().state().max_queue, 1U);
}
TEST_F(ScopedKeysOpenCleanup, open_whenRetryCloseWaitsForNativeEntry_retainsStorageUntilEntryReturns) {
  provider().state().persist_fail_at = 1;
  failed_open(RASP_SK_OP_STORAGE_UNAVAILABLE);
  ASSERT_EQ(provider().state().queue.size(), 1U);
  provider().state().close_fail = false;
  provider().state().on_main = true;
  std::promise<void> entered;
  std::promise<void> release;
  const auto released = release.get_future().share();
  provider().state().during_main = [&] {
    entered.set_value();
    released.wait();
  };
  auto caller = std::async(std::launch::async, [this] { return open(); });
  entered.get_future().wait();
  auto worker = std::async(std::launch::async, [this] { return provider().step(); });
  EXPECT_EQ(worker.wait_for(std::chrono::milliseconds(20)), std::future_status::timeout);
  EXPECT_TRUE(provider().state().storage_owned);
  EXPECT_EQ(closes(), 1U);
  EXPECT_FALSE(rasp::keys::detach_platform(provider()));
  release.set_value();
  EXPECT_EQ(caller.get(), RASP_SK_CALL_WRONG_THREAD);
  EXPECT_TRUE(worker.get());
  EXPECT_EQ(closes(), 2U);
  EXPECT_FALSE(provider().state().storage_owned);
  provider().state().during_main = {};
  provider().state().on_main = false;
  ASSERT_EQ(open(), RASP_SK_CALL_OK);
  EXPECT_EQ(opened().operation_status, RASP_SK_OP_OK);
}
}  // namespace
