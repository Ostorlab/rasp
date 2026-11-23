/// end_process: the adapter that lets the shared core panic path (which calls an EndProcess function pointer) end the
/// process through the inlined termination primitives in terminate.h.
///
/// The real termination lives in terminate_now (panic/terminate.h), which is always-inlined into each detection site
/// so there is no one function for an attacker to replace. This named function exists only because the shared
/// `panic_on_detection`/`arm_panic` core (used by Android too) takes an `EndProcess` function pointer; it forwards to
/// the inlined primitive. The detection sites do not rely on it alone: they also inline terminate_now directly, so
/// neutralising this symbol or the function pointer does not keep a tampered app alive.

#include "panic/end_process.h"

#include "panic/terminate.h"

namespace rasp::ios {

void end_process() noexcept { terminate_now(); }

}  // namespace rasp::ios
