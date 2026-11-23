/// A test double for rasp::ios::end_process, so the guard and VM tests can exercise the tamper (kill) path without the
/// real arm64 XNU exit system call, which does not compile or run on the host. The stub records that end_process was
/// called and longjmps back to a point the test set, so a death path becomes an observable, recoverable event.

#pragma once

#include <csetjmp>

namespace rasp::ios::testing {

/// The jump buffer the stub returns to. A test calls `setjmp(end_process_jump)` before running the code under test and
/// arms the stub; when the code calls end_process, control returns to the setjmp with a non-zero value.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): a test double's recorded state.
extern std::jmp_buf end_process_jump;

/// Whether the stub is armed to longjmp. A test sets it true after setjmp; when false the stub aborts, so an unexpected
/// end_process in a test that did not arm it fails loudly rather than longjmping to a stale buffer.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): a test double's recorded state.
extern bool end_process_armed;

/// How many times the stub was invoked since the last reset. A test checks this to assert the kill path was reached.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): a test double's recorded state.
extern int end_process_calls;

}  // namespace rasp::ios::testing
