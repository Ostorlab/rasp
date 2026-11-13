/// Test-only owned OpenSSL provider and actual HD02 gate fixtures; no OS/hardware claim.
#pragma once
#include <array>
#include <atomic>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "platform.h"

namespace fixture {
/// Decode independently frozen lowercase hex.
std::vector<std::uint8_t> unhex(std::string_view value);
/// True only in the separately compiled real report-only policy fixture.
[[nodiscard]] bool report_only();
/// Fixed compile-time test policy, real typed cycle publication, no replacement evaluator.
void publish(std::int64_t tracer = 0, bool unavailable = false);
/// Shared suspend-inclusive fixture boundary used by both actual gate and companion clocks.
std::atomic<std::uint64_t>& ticks();
/// Build the host-owned immutable opt-in config, not from runtime policy info.
RaspScopedKeyClientSpecV1 config(bool biometry = false, std::uint32_t spaces = 1);
/// Exact public namespace reference used only to identify fixture-owned keys.
std::string identity(const RaspScopedKeyTokenV1& token);
/// Explicitly controlled fixture data; it does not model or replace shared Service state.
struct ProviderState {
  bool on_main = false;
  bool random_fail = false;
  bool constant_entropy = false;
  bool clock_fail = false;
  bool close_fail = false;
  bool schedule_fail = false;
  bool erase_fail = false;
  bool storage_owned = false;
  bool immediate_auth = false;
  bool publish_before_error = false;
  int persist_fail_at = -1;
  std::uint32_t auth_status = RASP_SK_OP_OK;
  std::uint32_t create_status = RASP_SK_OP_OK;
  std::uint32_t sign_status = RASP_SK_OP_OK;
  std::uint32_t describe_status = RASP_SK_OP_OK;
  std::atomic<std::uint32_t> calls{0};
  std::atomic<std::uint32_t> random_calls{0};
  std::atomic<std::uint32_t> generates{0};
  std::atomic<std::uint32_t> signs{0};
  std::atomic<std::uint32_t> prompts{0};
  std::atomic<std::uint32_t> erases{0};
  std::atomic<std::uint32_t> persists{0};
  rasp::keys::PlatformDiagnostic persist_diagnostic{};
  rasp::keys::PlatformDiagnostic create_diagnostic{};
  rasp::keys::PlatformDiagnostic describe_diagnostic{};
  rasp::keys::PlatformDiagnostic auth_diagnostic{};
  rasp::keys::PlatformDiagnostic prepare_diagnostic{};
  rasp::keys::PlatformDiagnostic sign_diagnostic{};
  rasp::keys::PlatformDiagnostic erase_diagnostic{};
  std::function<void()> during_prepare;
  std::function<void()> during_schedule;
  std::uint32_t max_queue = 0;
  std::vector<std::uint8_t> disk;
  std::vector<std::vector<std::uint8_t>> history;
  std::vector<std::uint8_t> last_message;
  std::deque<RaspScopedKeyTokenV1> queue;
  std::vector<RaspScopedKeyTokenV1> auth_jobs;
  std::vector<std::string> deleted;
  std::function<void()> during_sign;
  std::function<void()> during_create;
  std::function<void()> during_describe;
  std::function<void()> during_persist;
  std::function<void()> during_main;
  std::function<void()> during_clock;
  std::function<void()> during_close;
  std::mutex mutex;
};
/// Pure platform-boundary fixture: owned generated test keys and controlled scheduling/storage.
class Provider final : public rasp::keys::Platform {
 public:
  Provider() = default;
  Provider(const Provider&) = delete;
  Provider& operator=(const Provider&) = delete;
  Provider(Provider&&) = delete;
  Provider& operator=(Provider&&) = delete;
  /// Owned boundary controls exposed only to tests.
  [[nodiscard]] ProviderState& state() { return state_; }
  [[nodiscard]] const ProviderState& state() const { return state_; }
  /// Release test keys after shared service is fully detached.
  ~Provider() override;
  bool main_thread() override;
  bool random(std::span<std::uint8_t> output) override;
  bool clock(std::uint64_t& output) override;
  std::uint32_t open_storage(rasp::keys::Application& app, std::span<std::uint8_t> file, std::uint32_t& written,
                             bool& exists) override;
  std::uint32_t persist(std::span<const std::uint8_t> file, rasp::keys::PlatformDiagnostic& diagnostic) override;
  bool close_storage() override;
  bool schedule(const RaspScopedKeyTokenV1& job) override;
  std::uint32_t create(const rasp::keys::KeyReference& key, RaspScopedKeyInfoV1& measured,
                       rasp::keys::CreationReceipt& receipt, rasp::keys::PlatformDiagnostic& diagnostic) override;
  std::uint32_t describe(const rasp::keys::KeyReference& key, RaspScopedKeyInfoV1& measured,
                         rasp::keys::PlatformDiagnostic& diagnostic) override;
  std::uint32_t authenticate(const RaspScopedKeyTokenV1& job, const rasp::keys::KeyReference& key,
                             std::span<std::uint8_t> bytes, rasp::keys::PlatformDiagnostic& diagnostic) override;
  std::uint32_t prepare_sign(const rasp::keys::KeyReference& key, std::span<const std::uint8_t> message_bytes,
                             std::span<std::uint8_t> bytes, rasp::keys::PlatformDiagnostic& diagnostic) override;
  std::uint32_t sign(const rasp::keys::KeyReference& key, std::span<std::uint8_t> bytes, std::span<std::uint8_t> der,
                     std::uint32_t& written, rasp::keys::PlatformDiagnostic& diagnostic) override;
  std::uint32_t erase(const rasp::keys::KeyReference& key, const rasp::keys::CleanupProof& proof,
                      rasp::keys::PlatformDiagnostic& diagnostic) override;
  void cancel(const RaspScopedKeyTokenV1& job) override;
  void release(std::span<std::uint8_t> bytes) override;
  /// Test OS-store persistence across actual exec; never part of the shipped companion archive.
  [[nodiscard]] bool save_store(const std::filesystem::path& directory);
  [[nodiscard]] bool load_store(const std::filesystem::path& directory);
  /// Controlled external OS mutation, not SDK create/adopt/overwrite behavior.
  [[nodiscard]] bool replace_external(const rasp::keys::KeyReference& key);
  [[nodiscard]] std::size_t stored_keys() const { return keys_.size(); }
  /// Run one previously posted job, without a fake shared-state transition.
  bool step();
  /// Drain a finite fixture queue; pending auth/hung jobs remain explicitly outstanding.
  void drain();

 private:
  ProviderState state_{};
  std::map<std::string, EVP_PKEY*> keys_;
};
/// Independently reconstruct message bytes using vectors/OpenSSL hashing, not production encoding functions.
std::vector<std::uint8_t> message(const RaspScopedKeyInfoV1& key, const RaspScopedKeyClientSpecV1& client,
                                  const RaspScopedKeySignInputV1& sign);
/// Verify with a separately imported public point and OpenSSL, never the fixture's private key.
bool verify(const RaspScopedKeyInfoV1& key, std::span<const std::uint8_t> message_bytes,
            const RaspScopedKeyValueSignatureV1& signature);
}  // namespace fixture
