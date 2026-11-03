/// Tests for the iOS debugger checks.

#include "checks/debugger.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <unistd.h>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <mach/exception_types.h>
#include <mach/kern_return.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/task.h>
#include <variant>
#endif

namespace rasp::ios::checks {
namespace {

#ifdef __APPLE__
TEST(Debugger, observeTraced_whenNoDebuggerIsAttached_reportsFalse) {
  EXPECT_EQ(observe_traced(),
            (Observation{.signal = "dbg.traced", .source = "sysctl", .status = Status::kOk, .value = false}));
}
#else
TEST(Debugger, observeTraced_whenTheSystemHasNoProcessFlags_reportsUnsupported) {
  EXPECT_EQ(observe_traced(),
            (Observation{.signal = "dbg.traced", .source = "sysctl", .status = Status::kUnsupported, .value = {}}));
}
#endif

#if defined(__APPLE__) && defined(__aarch64__)
TEST(Debugger, observeTracedSyscall_whenNoDebuggerIsAttached_reportsFalse) {
  EXPECT_EQ(observe_traced_syscall(),
            (Observation{.signal = "dbg.traced", .source = "sysctl_syscall", .status = Status::kOk, .value = false}));
}

TEST(Debugger, observeTracedSyscall_whenCalled_agreesWithTheLibcSource) {
  const Observation through_libc = observe_traced();
  const Observation direct = observe_traced_syscall();

  EXPECT_EQ(direct.status, through_libc.status);
  EXPECT_EQ(direct.value, through_libc.value);
}

TEST(Debugger, observeParentSyscall_whenCalled_reportsTheParentProcessId) {
  EXPECT_EQ(observe_parent_syscall(), (Observation{.signal = "dbg.parent",
                                                   .source = "sysctl_syscall",
                                                   .status = Status::kOk,
                                                   .value = static_cast<std::int64_t>(getppid())}));
}
#else
TEST(Debugger, observeTracedSyscall_whenTheSystemIsNotAppleOnArm64_reportsUnsupported) {
  EXPECT_EQ(
      observe_traced_syscall(),
      (Observation{.signal = "dbg.traced", .source = "sysctl_syscall", .status = Status::kUnsupported, .value = {}}));
}

TEST(Debugger, observeParentSyscall_whenTheSystemIsNotAppleOnArm64_reportsUnsupported) {
  EXPECT_EQ(
      observe_parent_syscall(),
      (Observation{.signal = "dbg.parent", .source = "sysctl_syscall", .status = Status::kUnsupported, .value = {}}));
}
#endif

TEST(Debugger, observeParent_whenCalled_reportsTheParentProcessId) {
  EXPECT_EQ(observe_parent(), (Observation{.signal = "dbg.parent",
                                           .source = "getppid",
                                           .status = Status::kOk,
                                           .value = static_cast<std::int64_t>(getppid())}));
}

#ifdef __APPLE__
TEST(Debugger, observeExceptionPorts_whenABreakpointPortIsSet_addsTheBreakpointMaskAndReleasesThePortRight) {
  mach_port_t port = MACH_PORT_NULL;
  ASSERT_EQ(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port), KERN_SUCCESS);
  ASSERT_EQ(mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND), KERN_SUCCESS);
  ASSERT_EQ(task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, MACH_PORT_NULL, EXCEPTION_DEFAULT,
                                     THREAD_STATE_NONE),
            KERN_SUCCESS);
  const Observation without_port = observe_exception_ports();
  ASSERT_EQ(task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, port, EXCEPTION_DEFAULT, THREAD_STATE_NONE),
            KERN_SUCCESS);
  mach_port_urefs_t send_rights_before = 0;
  ASSERT_EQ(mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, &send_rights_before), KERN_SUCCESS);
  const Observation with_port = observe_exception_ports();
  mach_port_urefs_t send_rights_after = 0;
  ASSERT_EQ(mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, &send_rights_after), KERN_SUCCESS);
  ASSERT_EQ(task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, MACH_PORT_NULL, EXCEPTION_DEFAULT,
                                     THREAD_STATE_NONE),
            KERN_SUCCESS);
  ASSERT_EQ(mach_port_deallocate(mach_task_self(), port), KERN_SUCCESS);
  ASSERT_EQ(mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1), KERN_SUCCESS);

  ASSERT_EQ(without_port.status, Status::kOk);
  ASSERT_TRUE(std::holds_alternative<std::int64_t>(without_port.value));
  const auto breakpoint_mask = static_cast<exception_mask_t>(EXC_MASK_BREAKPOINT);
  const auto mask_without_port = static_cast<exception_mask_t>(std::get<std::int64_t>(without_port.value));
  EXPECT_EQ(mask_without_port & breakpoint_mask, 0U);
  EXPECT_EQ(with_port, (Observation{.signal = "dbg.exception_ports",
                                    .source = "task_get_exception_ports",
                                    .status = Status::kOk,
                                    .value = static_cast<std::int64_t>(mask_without_port | breakpoint_mask)}));
  EXPECT_EQ(send_rights_after, send_rights_before);
}
#else
TEST(Debugger, observeExceptionPorts_whenTheSystemHasNoExceptionPorts_reportsUnsupported) {
  EXPECT_EQ(observe_exception_ports(), (Observation{.signal = "dbg.exception_ports",
                                                    .source = "task_get_exception_ports",
                                                    .status = Status::kUnsupported,
                                                    .value = {}}));
}
#endif

TEST(Debugger, debugger_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(debugger(),
            (std::vector<Observation>{
                {.signal = "dbg.traced", .source = "sysctl", .status = Status::kUnsupported, .value = {}},
                {.signal = "dbg.traced", .source = "sysctl_syscall", .status = Status::kUnsupported, .value = {}},
                {.signal = "dbg.parent", .source = "getppid", .status = Status::kUnsupported, .value = {}},
                {.signal = "dbg.parent", .source = "sysctl_syscall", .status = Status::kUnsupported, .value = {}},
                {.signal = "dbg.exception_ports",
                 .source = "task_get_exception_ports",
                 .status = Status::kUnsupported,
                 .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::ios::checks
