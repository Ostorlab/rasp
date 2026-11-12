/// Test-only real signing and real owned typed policy publication; no production provider implementation.
#include "support.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <mutex>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "encoding.h"
#include "local_policy_state.h"
#include "platform.h"
#include "rasp/config.h"
#include "rasp/context.h"
#include "rasp/cycle.h"
#include "rasp/local_policy.h"
#include "rasp/observation.h"
#include "rasp/parse_config.h"
#include "rasp/scoped_key.h"

namespace fixture {
std::vector<std::uint8_t> unhex(std::string_view value) {
  std::vector<std::uint8_t> output;
  for (std::size_t index = 0; index < value.size(); index += 2) {
    output.push_back(static_cast<std::uint8_t>(std::stoul(std::string(value.substr(index, 2)), nullptr, 16)));
  }
  return output;
}
std::atomic<std::uint64_t>& ticks() {
  static constinit std::atomic<std::uint64_t> value{1000000000};
  return value;
}
namespace {
/// Exact controlled external clock boundary; production gate/evaluator remain unchanged.
std::optional<std::int64_t> clock() { return static_cast<std::int64_t>(ticks().load()); }
/// Immutable test policy independently specifies one actually supported debugger predicate.
rasp::Config policy() {
  return rasp::parse_config(
      R"({"build_id":"test","checks":["debugger"],"local_policy":{"schema_version":1,"engine_version":1,"policy_id":"demo","policy_version":1,"mode":"gate","scope":"host_calls_only","platform":"android","catalogue_id":"2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d","report_schema_version":1,"report_reason_version":1,"native_metadata_version":1,"operations":[{"name":"append_demo_receipt","max_evidence_age_ms":75000,"max_cycle_duration_ms":5000,"rules":[{"rule_id":"native.android.dbg.tracer_pid.proc_status","rule_version":1}]}]}})");
}
/// Independent big-endian writer, deliberately separate from the implementation's Writer.
void number(std::vector<std::uint8_t>& output, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::uint8_t>(value >> static_cast<unsigned>(shift)));
  }
}
/// Independent opaque byte append.
void append(std::vector<std::uint8_t>& output, std::span<const std::uint8_t> bytes) {
  output.insert(output.end(), bytes.begin(), bytes.end());
}
/// Independent length-prefixed field.
void field(std::vector<std::uint8_t>& output, std::span<const std::uint8_t> bytes) {
  number(output, static_cast<std::uint32_t>(bytes.size()));
  append(output, bytes);
}
}  // namespace
void publish(std::int64_t tracer, bool unavailable) {
  auto* owner = rasp::process_local_policy();
  const auto selected = policy();
  if (owner == nullptr) {
    owner = rasp::install_local_policy(std::make_unique<rasp::LocalPolicyState>(selected, "android", clock));
  }
  ASSERT_NE(owner, nullptr);
  owner->begin_cycle();
  const std::vector<rasp::Observation> input{
      {
          .signal = "dbg.tracer_pid",
          .source = "proc_status",
          .status = unavailable ? rasp::Status::kError : rasp::Status::kOk,
          .value = tracer,
      },
      rasp::observed("dbg.tracer_pid", "proc_status_syscall", std::int64_t{0}),
      rasp::observed("dbg.java_debugger", "debug_api", false),
      rasp::observed("dbg.java_debugger", "jdwp_threads", std::vector<std::string>{}),
  };
  rasp::CycleMonitor monitor;
  rasp::plugins::Context context;
  owner->finish_cycle(monitor.run(
      selected, rasp::cycle_catalogue("android"), {}, context,
      [](const rasp::Config&, const void* value) { return *static_cast<const std::vector<rasp::Observation>*>(value); },
      &input));
}
RaspScopedKeyClientSpecV1 config(bool biometry, std::uint32_t spaces) {
  RaspScopedKeyClientSpecV1 output{};
  output.abi_version = 1;
  output.struct_size = sizeof(output);
  output.signing_scope_length = 10;
  std::memcpy(std::span(output.signing_scope).data(), "owned-test", 10);
  output.namespace_count = spaces;
  const auto hash = unhex(rasp::local_policy_hash(policy().local_policy.canonical_json));
  for (std::size_t index = 0; index < spaces; ++index) {
    auto& space = std::span(output.namespaces)[index];
    space.selector = static_cast<std::uint32_t>(index + 1);
    space.backend_requirement = 1;
    space.auth_requirement = biometry ? 2U : 1U;
    space.lock_requirement = 1;
    space.gate_mode = 1;
    space.namespace_length = 8;
    std::memcpy(std::span(space.namespace_name).data(), "receipts", 8);
    space.namespace_name[7] = static_cast<std::uint8_t>('a' + index);
    space.purpose_length = 19;
    std::memcpy(std::span(space.purpose).data(), "transaction_receipt", 19);
    space.gate_operation_length = 19;
    std::memcpy(std::span(space.gate_operation).data(), "append_demo_receipt", 19);
    std::ranges::copy(hash, std::span(space.expected_policy_sha256).begin());
  }
  return output;
}
std::string identity(const RaspScopedKeyTokenV1& token) { return {std::begin(token.bytes), std::end(token.bytes)}; }
Provider::~Provider() {
  for (const auto& [name, key] : keys_) {
    static_cast<void>(name);
    EVP_PKEY_free(key);
  }
}
bool Provider::main_thread() {
  state_.calls.fetch_add(1);
  if (state_.during_main) {
    state_.during_main();
  }
  return state_.on_main;
}
bool Provider::random(std::span<std::uint8_t> output) {
  state_.random_calls.fetch_add(1);
  state_.calls.fetch_add(1);
  if (state_.constant_entropy) {
    std::ranges::fill(output, 7);
    return true;
  }
  if (state_.random_fail) {
    return false;
  }
  if (output.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return false;
  }
  return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}
bool Provider::clock(std::uint64_t& output) {
  if (state_.during_clock) {
    state_.during_clock();
  }
  state_.calls.fetch_add(1);
  output = ticks().load();
  return !state_.clock_fail;
}
std::uint32_t Provider::open_storage(rasp::keys::Application& app, std::span<std::uint8_t> file, std::uint32_t& written,
                                     bool& exists) {
  state_.calls.fetch_add(1);
  if (state_.storage_owned) {
    return RASP_SK_OP_BUSY;
  }
  state_.storage_owned = true;
  app.length = 19;
  std::memcpy(app.name.data(), "co.ostorlab.fixture", 19);
  std::tie(written, exists) = std::tuple{static_cast<std::uint32_t>(state_.disk.size()), !state_.disk.empty()};
  if (state_.disk.size() <= file.size()) {
    std::ranges::copy(state_.disk, file.begin());
  }
  return RASP_SK_OP_OK;
}
std::uint32_t Provider::persist(std::span<const std::uint8_t> file) {
  state_.calls.fetch_add(1);
  ++state_.persists;
  if (state_.during_persist) {
    state_.during_persist();
  }
  if (std::cmp_equal(state_.persist_fail_at, state_.persists.load())) {
    if (state_.publish_before_error) {
      state_.disk.assign(file.begin(), file.end());
    }
    return RASP_SK_OP_STORAGE_UNAVAILABLE;
  }
  state_.disk.assign(file.begin(), file.end());
  return RASP_SK_OP_OK;
}
bool Provider::close_storage() {
  if (state_.during_close) {
    state_.during_close();
  }
  state_.calls.fetch_add(1);
  if (state_.close_fail) {
    return false;
  }
  state_.storage_owned = false;
  return true;
}
bool Provider::schedule(const RaspScopedKeyTokenV1& job) {
  state_.calls.fetch_add(1);
  if (state_.schedule_fail) {
    return false;
  }
  const std::scoped_lock lock(state_.mutex);
  state_.queue.push_back(job);
  state_.max_queue = std::max(state_.max_queue, static_cast<std::uint32_t>(state_.queue.size()));
  return true;
}
std::uint32_t Provider::create(const rasp::keys::KeyReference& key, RaspScopedKeyInfoV1& measured) {
  state_.calls.fetch_add(1);
  ++state_.generates;
  if (state_.during_create) {
    state_.during_create();
  }
  if (state_.create_status != RASP_SK_OP_OK) {
    return state_.create_status;
  }
  EVP_PKEY_CTX* generator = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (generator == nullptr) {
    return RASP_SK_OP_PLATFORM_ERROR;
  }
  auto group = std::to_array("prime256v1");
  std::array parameters{
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group.data(), 0),
      OSSL_PARAM_construct_end(),
  };
  EVP_PKEY* generated = nullptr;
  const bool okay = EVP_PKEY_keygen_init(generator) == 1 &&
                    EVP_PKEY_CTX_set_params(generator, parameters.data()) == 1 &&
                    EVP_PKEY_generate(generator, &generated) == 1;
  EVP_PKEY_CTX_free(generator);
  if (!okay) {
    EVP_PKEY_free(generated);
    return RASP_SK_OP_PLATFORM_ERROR;
  }
  {
    const std::scoped_lock lock(state_.mutex);
    keys_.emplace(identity(key.key_id), generated);
  }
  return describe(key, measured);
}
std::uint32_t Provider::describe(const rasp::keys::KeyReference& key, RaspScopedKeyInfoV1& measured) {
  state_.calls.fetch_add(1);
  if (state_.describe_status != RASP_SK_OP_OK) {
    return state_.describe_status;
  }
  const std::scoped_lock lock(state_.mutex);
  const auto found = keys_.find(identity(key.key_id));
  if (found == keys_.end()) {
    return RASP_SK_OP_NOT_FOUND;
  }
  std::size_t written = 0;
  if (EVP_PKEY_get_octet_string_param(found->second, OSSL_PKEY_PARAM_PUB_KEY,
                                      std::span(measured.public_key_x963).data(), 65, &written) != 1 ||
      written != 65) {
    return RASP_SK_OP_PLATFORM_ERROR;
  }
  measured.provenance.backend = 1;
  measured.provenance.security_level = 2;
  measured.provenance.source = 1;
  measured.provenance.key_origin = 1;
  measured.provenance.private_export = 1;
  measured.provenance.auth_observed_present = 1;
  measured.provenance.auth_observed = key.space.auth_requirement;
  measured.provenance.lock_observed_present = 1;
  measured.provenance.lock_observed = key.space.lock_requirement;
  measured.provenance.accessibility = 1;
  measured.provenance.backup = 1;
  return RASP_SK_OP_OK;
}
std::uint32_t Provider::authenticate(const RaspScopedKeyTokenV1& job, const rasp::keys::KeyReference& key,
                                     std::span<std::uint8_t> bytes) {
  state_.calls.fetch_add(1);
  static_cast<void>(key);
  ++state_.prompts;
  if (state_.auth_status != RASP_SK_OP_OK) {
    return state_.auth_status;
  }
  bytes[0] = 0x79;
  state_.auth_jobs.push_back(job);
  if (state_.immediate_auth) {
    std::thread callback([job] { rasp::keys::authenticated(job, RASP_SK_OP_OK); });
    callback.join();
  }
  return RASP_SK_OP_OK;
}
std::uint32_t Provider::sign(const rasp::keys::KeyReference& key, std::span<const std::uint8_t> message_bytes,
                             std::span<std::uint8_t> bytes, std::span<std::uint8_t> der, std::uint32_t& written) {
  state_.calls.fetch_add(1);
  if (bytes.size() != 1024 || der.size() != 72) {
    return RASP_SK_OP_INTERNAL_ERROR;
  }
  if (key.space.auth_requirement == 2 && bytes[0] != 0x79) {
    return RASP_SK_OP_AUTH_REQUIRED;
  }
  ++state_.signs;
  if (state_.during_sign) {
    state_.during_sign();
  }
  if (state_.sign_status != RASP_SK_OP_OK) {
    return state_.sign_status;
  }
  const std::scoped_lock lock(state_.mutex);
  const auto found = keys_.find(identity(key.key_id));
  if (found == keys_.end()) {
    return RASP_SK_OP_NOT_FOUND;
  }
  state_.last_message.assign(message_bytes.begin(), message_bytes.end());
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  std::size_t length = der.size();
  const bool okay = ctx != nullptr && EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, found->second) == 1 &&
                    EVP_DigestSign(ctx, der.data(), &length, message_bytes.data(), message_bytes.size()) == 1;
  EVP_MD_CTX_free(ctx);
  written = static_cast<std::uint32_t>(length);
  return okay ? RASP_SK_OP_OK : RASP_SK_OP_PLATFORM_ERROR;
}
std::uint32_t Provider::erase(const rasp::keys::KeyReference& key) {
  state_.calls.fetch_add(1);
  const std::scoped_lock lock(state_.mutex);
  ++state_.erases;
  state_.deleted.push_back(identity(key.key_id));
  if (state_.erase_fail) {
    return RASP_SK_OP_PLATFORM_ERROR;
  }
  const auto found = keys_.find(identity(key.key_id));
  if (found != keys_.end()) {
    EVP_PKEY_free(found->second);
    keys_.erase(found);
  }
  return RASP_SK_OP_OK;
}
void Provider::cancel(const RaspScopedKeyTokenV1& job) {
  state_.calls.fetch_add(1);
  static_cast<void>(job);
}
void Provider::release(std::span<std::uint8_t> bytes) {
  state_.calls.fetch_add(1);
  std::ranges::fill(bytes, 0);
}
bool Provider::step() {
  RaspScopedKeyTokenV1 token{};
  {
    const std::scoped_lock lock(state_.mutex);
    if (state_.queue.empty()) {
      return false;
    }
    token = state_.queue.front();
    state_.queue.pop_front();
  }
  rasp::keys::run_job(token);
  return true;
}
void Provider::drain() {
  for (std::size_t index = 0; index < 100 && step(); ++index) {
  }
}
std::vector<std::uint8_t> message(const RaspScopedKeyInfoV1& key, const RaspScopedKeyClientSpecV1& client,
                                  const RaspScopedKeySignInputV1& sign) {
  const auto& space = client.namespaces[0];
  std::vector<std::uint8_t> output;
  constexpr std::string_view kDomain = "Ostorlab.RASP.ScopedSign";
  output.insert(output.end(), kDomain.begin(), kDomain.end());
  output.push_back(0);
  number(output, 1);
  number(output, 1);
  std::vector<std::uint8_t> app;
  const std::string name = "co.ostorlab.fixture";
  const std::vector<std::uint8_t> app_name(name.begin(), name.end());
  field(app, app_name);
  field(app, std::span(client.signing_scope).first(client.signing_scope_length));
  field(output, app);
  field(output, std::span(space.namespace_name).first(space.namespace_length));
  field(output, std::span(space.purpose).first(space.purpose_length));
  field(output, std::span(space.gate_operation).first(space.gate_operation_length));
  append(output, space.expected_policy_sha256);
  number(output, space.gate_mode);
  append(output, key.profile_sha256);
  append(output, key.key_id.bytes);
  append(output, key.public_key_x963);
  field(output, std::span(sign.audience).first(sign.audience_length));
  append(output, sign.transaction_id);
  append(output, sign.challenge);
  field(output, std::span(sign.transaction).first(sign.transaction_length));
  return output;
}
bool verify(const RaspScopedKeyInfoV1& key, std::span<const std::uint8_t> message_bytes,
            const RaspScopedKeyValueSignatureV1& signature) {
  EVP_PKEY_CTX* importer = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  auto group = std::to_array("prime256v1");
  auto point = std::to_array(key.public_key_x963);
  std::array parameters{
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group.data(), 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()),
      OSSL_PARAM_construct_end(),
  };
  EVP_PKEY* public_key = nullptr;
  const bool imported = importer != nullptr && EVP_PKEY_fromdata_init(importer) == 1 &&
                        EVP_PKEY_fromdata(importer, &public_key, EVP_PKEY_PUBLIC_KEY, parameters.data()) == 1;
  EVP_PKEY_CTX_free(importer);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  const bool okay = imported && ctx != nullptr &&
                    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) == 1 &&
                    EVP_DigestVerify(ctx, std::span(signature.der).data(), signature.der_length, message_bytes.data(),
                                     message_bytes.size()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(public_key);
  return okay;
}
}  // namespace fixture
