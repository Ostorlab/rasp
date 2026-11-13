/// Actual exec creates a cold Service/registry; only the durable OS store is a fixture.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <span>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>
#include <vector>

#include "encoding.h"
#include "manifest.h"
#include "platform.h"
#include "rasp/scoped_key.h"
#include "support.h"
namespace {
std::vector<std::string> environment() {
  std::ifstream input("/proc/self/environ", std::ios::binary);
  std::vector<std::string> result;
  std::string value;
  while (std::getline(input, value, '\0')) {
    result.push_back(value);
  }
  return result;
}
std::string history_path() {
  constexpr std::string_view kPrefix = "RASP_SCOPED_HISTORY_STORE=";
  for (const auto& value : environment()) {
    if (value.starts_with(kPrefix)) {
      return value.substr(kPrefix.size());
    }
  }
  return {};
}

/// Every file is generated test data in one newly owned0700 directory, never a production key store.
class TemporaryStore {
 public:
  TemporaryStore() {
    auto name = std::to_array("/tmp/rasp-scoped-history-XXXXXX");
    const char* created = mkdtemp(name.data());
    if (created != nullptr) {
      path_ = created;
    }
  }
  TemporaryStore(const TemporaryStore&) = delete;
  TemporaryStore& operator=(const TemporaryStore&) = delete;
  TemporaryStore(TemporaryStore&&) = delete;
  TemporaryStore& operator=(TemporaryStore&&) = delete;
  ~TemporaryStore() {
    if (!path_.empty()) {
      std::error_code ignored;
      std::filesystem::remove_all(path_, ignored);
    }
  }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};
struct HistoryState {
  fixture::Provider provider;
  RaspScopedKeyClientSpecV1 spec{};
  RaspScopedKeyClientOpenedV1 client{};
  std::unique_ptr<RaspScopedKeySubmitV1> input = std::make_unique<RaspScopedKeySubmitV1>();
  std::unique_ptr<RaspScopedKeyTakeResultV1> result = std::make_unique<RaspScopedKeyTakeResultV1>();
};
class ColdHistory : public ::testing::TestWithParam<unsigned> {
 private:
  HistoryState state_;

 protected:
  [[nodiscard]] HistoryState& state() { return state_; }
  void SetUp() override {
    fixture::publish();
    fixture::publish();
    state().spec = fixture::config(false, 2);
    ASSERT_TRUE(rasp::keys::attach_platform(state().provider));
  }
  void TearDown() override {
    close();
    state().provider.drain();
    EXPECT_TRUE(rasp::keys::detach_platform(state().provider));
  }
  void close() {
    if (!rasp::keys::nonzero(state().client.client)) {
      return;
    }
    RaspScopedKeyControlV1 input{};
    input.abi_version = 1;
    input.struct_size = sizeof(input);
    input.client = state().client.client;
    input.action = RASP_SK_CLOSE_CLIENT;
    RaspScopedKeyControlResultV1 out{};
    EXPECT_EQ(rasp_scoped_key_control_v1(&input, sizeof(input), &out, sizeof(out)), RASP_SK_CALL_OK);
    state().provider.drain();
  }
  void open(std::uint32_t expected = RASP_SK_OP_OK) {
    ASSERT_EQ(
        rasp_scoped_key_client_open_v1(&state().spec, sizeof(state().spec), &state().client, sizeof(state().client)),
        RASP_SK_CALL_OK);
    ASSERT_EQ(state().client.operation_status, expected);
  }
  RaspScopedKeyAdmissionV1 submit(RaspScopedKeyOperationV1 operation, std::size_t space = 0,
                                  RaspScopedKeyTokenV1 key = {}) {
    *state().input = {};
    auto& in = *state().input;
    in.abi_version = 1;
    in.struct_size = sizeof(in);
    in.operation = operation;
    in.request_ttl_ms = 60000;
    in.client = state().client.client;
    in.namespace_handle = std::span(state().client.namespaces)[space].namespace_handle;
    if (operation == RASP_SK_REOPEN || operation == RASP_SK_DELETE) {
      in.input.key_id = key;
    }
    RaspScopedKeyAdmissionV1 out{};
    EXPECT_EQ(rasp_scoped_key_submit_v1(&in, sizeof(in), &out, sizeof(out)), RASP_SK_CALL_OK);
    return out;
  }
  void take(const RaspScopedKeyTokenV1& token) {
    RaspScopedKeyTakeRequestV1 in{};
    in.abi_version = 1;
    in.struct_size = sizeof(in);
    in.client = state().client.client;
    in.request = token;
    ASSERT_EQ(rasp_scoped_key_take_v1(&in, sizeof(in), state().result.get(), sizeof(*state().result)), RASP_SK_CALL_OK);
  }
  RaspScopedKeyValueKeyV1 create(std::size_t space = 0) {
    const auto admission = submit(RASP_SK_CREATE, space);
    EXPECT_EQ(admission.admission_state, RASP_SK_ACCEPTED);
    state().provider.drain();
    take(admission.request);
    EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
    return state().result->completion.value.key;
  }
  static void spawn(const std::filesystem::path& path) {
    auto values = environment();
    values.push_back("RASP_SCOPED_HISTORY_STORE=" + path.string());
    std::vector<char*> env;
    env.reserve(values.size() + 1);
    for (auto& value : values) {
      env.push_back(value.data());
    }
    env.push_back(nullptr);
    const auto* test = ::testing::UnitTest::GetInstance()->current_test_info();
    std::array<std::string, 2> args{
        std::filesystem::read_symlink("/proc/self/exe").string(),
        "--gtest_filter=" + std::string(test->test_suite_name()) + "." + test->name(),
    };
    std::array<char*, 3> argv{args[0].data(), args[1].data(), nullptr};
    pid_t pid = 0;
    const int spawned = posix_spawn(&pid, args[0].c_str(), nullptr, nullptr, argv.data(), env.data());
    ASSERT_EQ(spawned, 0);
    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
  }
  void parent() {
    open();
    const auto key = create();
    ASSERT_GE(state().provider.state().history.size(), 4U);
    const auto stage = GetParam();
    std::size_t snapshot_index = 2;
    if (stage == 0 || stage == 7) {
      snapshot_index = 1;
    } else if (stage == 2) {
      snapshot_index = 3;
    }
    auto snapshot = std::span(state().provider.state().history)[snapshot_index];
    auto manifest = std::make_unique<rasp::keys::Manifest>();
    ASSERT_TRUE(rasp::keys::decode_manifest(snapshot, *manifest));
    rasp::keys::KeyReference reference{};
    reference.generation = manifest->generation;
    reference.key_id = key.info.key_id;
    std::ranges::copy(key.info.profile_sha256, reference.profile_sha256.begin());
    if (stage == 3) {
      ASSERT_TRUE(state().provider.replace_external(reference));
    }
    if (stage == 4) {
      manifest->records[0].info.public_key_x963[1] ^= std::uint8_t{1};
      ASSERT_TRUE(rasp::keys::encode_manifest(*manifest, snapshot));
    }
    if (stage == 6) {
      state().provider.state().erase_fail = true;
      const auto erase = submit(RASP_SK_DELETE, 0, key.info.key_id);
      state().provider.drain();
      take(erase.request);
      EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
      snapshot = state().provider.state().disk;
    }
    if (stage == 7) {
      rasp::keys::PlatformDiagnostic diagnostic;
      ASSERT_EQ(state().provider.erase(reference, rasp::keys::cleanup_proof(key.info), diagnostic), RASP_SK_OP_OK);
    }
    close();
    state().provider.state().disk = snapshot;
    const TemporaryStore store;
    ASSERT_FALSE(store.path().empty());
    ASSERT_TRUE(state().provider.save_store(store.path()));
    spawn(store.path());
  }
  void child(const std::filesystem::path& path) {
    std::cout << "cold-exec process=" << getpid() << " history=" << GetParam()
              << " uses fresh Service and retained fixture OS store\n";
    ASSERT_TRUE(state().provider.load_store(path));
    auto manifest = std::make_unique<rasp::keys::Manifest>();
    ASSERT_TRUE(rasp::keys::decode_manifest(state().provider.state().disk, *manifest));
    const auto key_id = manifest->records[0].info.key_id;
    const auto stage = GetParam();
    state().provider.state().erase_fail = stage == 5;
    open(stage == 4 ? RASP_SK_OP_STORAGE_CORRUPT : RASP_SK_OP_OK);
    EXPECT_EQ(state().provider.state().generates.load(), 0U);
    if (stage == 4) {
      EXPECT_EQ(state().provider.stored_keys(), 1U);
      EXPECT_EQ(state().provider.state().erases.load(), 0U);
      return;
    }
    if (stage == 0 || stage == 3 || stage == 5) {
      EXPECT_EQ(state().provider.stored_keys(), 1U);
      EXPECT_EQ(submit(RASP_SK_REOPEN, 0, key_id).operation_status, RASP_SK_OP_CLEANUP_PENDING);
      const auto reset = submit(RASP_SK_RESET_NAMESPACE);
      ASSERT_EQ(reset.admission_state, RASP_SK_ACCEPTED);
      state().provider.drain();
      take(reset.request);
      EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_CLEANUP_PENDING);
      EXPECT_EQ(state().provider.stored_keys(), 1U);
      auto remaining = std::make_unique<rasp::keys::Manifest>();
      ASSERT_TRUE(rasp::keys::decode_manifest(state().provider.state().disk, *remaining));
      EXPECT_TRUE(rasp::keys::same(remaining->records[0].info.key_id, key_id));
      create(1);
      EXPECT_EQ(state().provider.stored_keys(), 2U);
      if (stage == 5) {
        state().provider.state().erase_fail = false;
        close();
        open();
        EXPECT_EQ(state().provider.stored_keys(), 1U);
        EXPECT_EQ(submit(RASP_SK_REOPEN, 0, key_id).operation_status, RASP_SK_OP_NOT_FOUND);
      }
    } else if (stage == 2) {
      const auto reopen = submit(RASP_SK_REOPEN, 0, key_id);
      ASSERT_EQ(reopen.admission_state, RASP_SK_ACCEPTED);
      state().provider.drain();
      take(reopen.request);
      EXPECT_EQ(state().result->completion.operation_status, RASP_SK_OP_OK);
      EXPECT_EQ(state().provider.stored_keys(), 1U);
      EXPECT_EQ(state().provider.state().generates.load(), 0U);
    } else {
      EXPECT_EQ(state().provider.stored_keys(), 0U);
      EXPECT_EQ(submit(RASP_SK_REOPEN, 0, key_id).operation_status, RASP_SK_OP_NOT_FOUND);
    }
  }
};
TEST_P(ColdHistory, restore_whenDurableCreationHistoryReentersColdProcess_neverAdoptsOrDeletesUnprovedAlias) {
  const std::string path = history_path();
  if (!path.empty()) {
    child(path);
  } else {
    parent();
  }
}
INSTANTIATE_TEST_SUITE_P(History, ColdHistory, ::testing::Values(0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U));
}  // namespace
