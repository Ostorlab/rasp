/// Tests for the guard VM interpreter. The interpreter runs a byte-code program over a blob; these drive hand-written
/// and packer-shaped programs over a caller-provided blob (run_guard_program_on_blob) so the dispatch, the branches,
/// and the kill opcode are all observable on the host. On the host own_code_hash returns zeros (no Mach-O self-read),
/// so the key the program derives is deterministic and a test can build the blob the program expects.

#include "selfdecrypt/vm.h"

#include <array>
#include <csetjmp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <gtest/gtest.h>

#include "ios/selfdecrypt/end_process_stub.h"
#include "selfdecrypt/atrest.h"
#include "selfdecrypt/chacha20.h"
#include "selfdecrypt/guard.h"
#include "selfdecrypt/seed.h"
#include "selfdecrypt/vm_ops.h"

namespace rasp::ios::selfdecrypt {
namespace {

constexpr std::size_t kBlobSize = 32;
constexpr std::array<std::uint8_t, 8> kMarker = {0x52, 0x41, 0x53, 0x50, 0x4f, 0x4b, 0x21, 0x21};  // "RASPOK!!"
constexpr std::array<std::uint8_t, kNonceSize> kNonce = {0x00, 0x00, 0x00, 0x00, 0x61, 0x74, 0x72, 0x73,
                                                         0x74, 0x67, 0x75, 0x61, 0x72, 0x64, 0x30, 0x31};

/// The default guard program the packer emits and the runtime links (ios/src/selfdecrypt/guard.cpp): derive, decrypt,
/// check, branch to kill on no-match, else set intact and halt.
constexpr std::array<unsigned char, 11> kGuardProgram = {
    static_cast<unsigned char>(OpCode::kDeriveKey),      static_cast<unsigned char>(OpCode::kDecryptBlob),
    static_cast<unsigned char>(OpCode::kCheckMarker),    static_cast<unsigned char>(OpCode::kJumpIfNoMatch),
    0x08,                                                static_cast<unsigned char>(OpCode::kSetIntact),
    static_cast<unsigned char>(OpCode::kJump),           0x0a,
    static_cast<unsigned char>(OpCode::kSetTampered),    static_cast<unsigned char>(OpCode::kKill),
    static_cast<unsigned char>(OpCode::kHalt),
};

/// The key the program derives on the host: derive_key(own_code_hash(), seed) with own_code_hash() == zeros off Apple.
[[nodiscard]] std::array<std::uint8_t, kKeyBytes> host_key() {
  std::array<std::uint8_t, kSeedBytes> seed{};
  reconstruct_seed(seed);
  const std::array<std::uint8_t, kKeyBytes> zero_code_hash{};
  return derive_key(zero_code_hash, seed);
}

/// The blob the packer would ship for the host: the marker encrypted under the host key.
[[nodiscard]] std::array<std::uint8_t, kBlobSize> genuine_blob() {
  std::array<std::uint8_t, kBlobSize> blob{};
  for (std::size_t i = 0; i < kMarker.size(); i++) {
    blob[i] = kMarker[i];
  }
  const std::array<std::uint8_t, kKeyBytes> key = host_key();
  chacha20_xor(blob.data(), blob.size(), key.data(), kNonce.data());
  return blob;
}

void reset_stub() {
  rasp::ios::testing::end_process_armed = false;
  rasp::ios::testing::end_process_calls = 0;
}

TEST(GuardVm, runGuardProgramOnBlob_whenBlobIsGenuine_isIntactAndDoesNotKill) {
  reset_stub();
  const std::array<std::uint8_t, kBlobSize> blob = genuine_blob();

  const GuardStatus status =
      run_guard_program_on_blob(kGuardProgram.data(), kGuardProgram.size(), std::span<const std::uint8_t>(blob));

  EXPECT_EQ(status, GuardStatus::kIntact);
  EXPECT_EQ(rasp::ios::testing::end_process_calls, 0);
}

TEST(GuardVm, runGuardProgramOnBlob_whenBlobIsPatched_reachesTheKillOpcode) {
  reset_stub();
  std::array<std::uint8_t, kBlobSize> blob = genuine_blob();
  blob[0] ^= 0x01;  // one wrong byte: the marker will not come back, as a wrong key would produce.

  GuardStatus status = GuardStatus::kIntact;
  // setjmp returns non-zero when the stubbed end_process longjmps back: the kill opcode was reached.
  if (setjmp(rasp::ios::testing::end_process_jump) == 0) {
    rasp::ios::testing::end_process_armed = true;
    status = run_guard_program_on_blob(kGuardProgram.data(), kGuardProgram.size(), std::span<const std::uint8_t>(blob));
    FAIL() << "the program did not reach the kill opcode on a patched blob";
  }
  rasp::ios::testing::end_process_armed = false;

  EXPECT_EQ(rasp::ios::testing::end_process_calls, 1);
  (void)status;
}

TEST(GuardVm, runGuardProgramOnBlob_whenProgramIsEmpty_isTamperedAndDoesNotKill) {
  reset_stub();
  const std::array<std::uint8_t, kBlobSize> blob = genuine_blob();

  const GuardStatus status = run_guard_program_on_blob(nullptr, 0, std::span<const std::uint8_t>(blob));

  EXPECT_EQ(status, GuardStatus::kTampered);
  EXPECT_EQ(rasp::ios::testing::end_process_calls, 0);
}

TEST(GuardVm, runGuardProgramOnBlob_whenOpcodeIsUnknown_isTampered) {
  reset_stub();
  const std::array<std::uint8_t, kBlobSize> blob = genuine_blob();
  const std::array<unsigned char, 2> program = {0xFE, static_cast<unsigned char>(OpCode::kHalt)};  // 0xFE: not an op.

  const GuardStatus status =
      run_guard_program_on_blob(program.data(), program.size(), std::span<const std::uint8_t>(blob));

  EXPECT_EQ(status, GuardStatus::kTampered);
  EXPECT_EQ(rasp::ios::testing::end_process_calls, 0);
}

TEST(GuardVm, runGuardProgramOnBlob_whenProgramLoopsForever_isTamperedRatherThanHanging) {
  reset_stub();
  const std::array<std::uint8_t, kBlobSize> blob = genuine_blob();
  const std::array<unsigned char, 2> program = {static_cast<unsigned char>(OpCode::kJump), 0x00};  // jumps to itself.

  const GuardStatus status =
      run_guard_program_on_blob(program.data(), program.size(), std::span<const std::uint8_t>(blob));

  EXPECT_EQ(status, GuardStatus::kTampered);
  EXPECT_EQ(rasp::ios::testing::end_process_calls, 0);
}

TEST(GuardVm, runGuardProgram_whenEmbeddedBlobIsZero_isAbsentAndDoesNotKill) {
  // The linked guard blob is the default zeros (no packer on the host), so the public entry reports absent without
  // running the program: an unpacked build must not be treated as tampered and must not be ended.
  reset_stub();

  const GuardStatus status = run_guard_program(kGuardProgram.data(), kGuardProgram.size());

  EXPECT_EQ(status, GuardStatus::kAbsent);
  EXPECT_EQ(rasp::ios::testing::end_process_calls, 0);
}

}  // namespace
}  // namespace rasp::ios::selfdecrypt
