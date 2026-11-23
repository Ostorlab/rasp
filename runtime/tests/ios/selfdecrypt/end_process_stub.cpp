/// The test double for rasp::ios::end_process. See end_process_stub.h. It replaces the real end_process at link time in
/// the guard and VM test executables.

#include "ios/selfdecrypt/end_process_stub.h"

#include <csetjmp>
#include <cstdlib>

#include "panic/end_process.h"

namespace rasp::ios::testing {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): a test double's recorded state.
std::jmp_buf end_process_jump;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): a test double's recorded state.
bool end_process_armed = false;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): a test double's recorded state.
int end_process_calls = 0;

}  // namespace rasp::ios::testing

namespace rasp::ios {

/// The stubbed end_process: records the call and longjmps back to the armed test. If the test did not arm the stub it
/// aborts, so an unexpected kill fails the test rather than jumping to a stale buffer. It never returns, so [[noreturn]]
/// still holds.
void end_process() noexcept {
  rasp::ios::testing::end_process_calls++;
  if (rasp::ios::testing::end_process_armed == false) {
    std::abort();
  }
  std::longjmp(rasp::ios::testing::end_process_jump, 1);
}

}  // namespace rasp::ios
