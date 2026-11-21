/// Tests for detect, panic_delay, arm_panic and panic_on_detection, as a release build compiles them, with a stand-in
/// for the end of the process that records the call instead.

#include "rasp/panic.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/config.h"
#include "rasp/observation.h"

namespace rasp {
namespace {

using std::chrono::milliseconds;
using std::chrono::steady_clock;
using Strings = std::vector<std::string>;

/// How long a test waits for an armed panic beyond its longest delay.
constexpr milliseconds kWaitMargin{2000};

/// How many times the stand-in ended the process.
///
/// @return The counter, which lives as long as the test process.
[[nodiscard]] std::atomic<int>& end_calls() {
  static std::atomic<int> calls{0};
  return calls;
}

/// The stand-in for the end of the process: counts the call and returns.
void record_end() noexcept { end_calls().fetch_add(1); }

/// Waits until the stand-in has been called `count` times, for at most `limit`.
///
/// @param count The number of calls to wait for.
/// @param limit The longest time to wait.
/// @return Whether the stand-in was called `count` times in time.
[[nodiscard]] bool wait_for_end_calls(int count, milliseconds limit) {
  const steady_clock::time_point deadline = steady_clock::now() + limit;
  while (end_calls().load() < count) {
    if (steady_clock::now() >= deadline) {
      return false;
    }
    std::this_thread::sleep_for(milliseconds{10});
  }
  return true;
}

/// What detect returns for one `kOk` observation of `signal` with `value`.
///
/// @param signal The observation's signal.
/// @param value The observation's value.
/// @return The detections.
[[nodiscard]] std::vector<Detection> detect_one(std::string_view signal, Value value) {
  const std::vector<Observation> observations = {observed(signal, "test", std::move(value))};
  return detect(observations);
}

/// One signal's verdict as the tests expect it: a value it detects and a value it doesn't.
struct SignalCase {
  /// The signal.
  std::string_view signal;
  /// A value that is a positive finding.
  Value positive;
  /// A value that isn't.
  Value negative;
};

TEST(Panic, detect_forEverySignal_detectsOnlyItsPositiveFinding) {
  const std::vector<SignalCase> cases = {
      {.signal = "dbg.tracer_pid", .positive = std::int64_t{4242}, .negative = std::int64_t{0}},
      {.signal = "dbg.traced", .positive = true, .negative = false},
      {.signal = "dbg.parent", .positive = std::int64_t{812}, .negative = std::int64_t{1}},
      {.signal = "dbg.java_debugger", .positive = true, .negative = false},
      {.signal = "emu.props", .positive = Strings{"ro.hardware=ranchu"}, .negative = Strings{}},
      {.signal = "emu.simulator", .positive = true, .negative = false},
      {.signal = "hook.maps_hits", .positive = Strings{"7f00 r-xp 0 0 0 /data/frida-agent.so"}, .negative = Strings{}},
      {.signal = "hook.rwx_regions", .positive = Strings{"7f00-7f10 rwxp 0 0 0"}, .negative = Strings{}},
      {.signal = "hook.threads", .positive = Strings{"gum-js-loop"}, .negative = Strings{}},
      {.signal = "hook.dyld_env", .positive = std::string("/usr/lib/tweak.dylib"), .negative = std::string()},
      {.signal = "hook.frida_port", .positive = true, .negative = false},
      {.signal = "hook.inline", .positive = Strings{"open"}, .negative = Strings{}},
      {.signal = "id.debuggable", .positive = true, .negative = false},
      {.signal = "integ.monitor_alive", .positive = false, .negative = true},
      {.signal = "jb.fs_paths", .positive = Strings{"/var/jb"}, .negative = Strings{}},
      {.signal = "jb.sandbox_escape", .positive = true, .negative = false},
      {.signal = "jb.fork_ok", .positive = true, .negative = false},
      {.signal = "mitm.tunnels", .positive = Strings{"tun0"}, .negative = Strings{}},
      {.signal = "mitm.proxies", .positive = Strings{"http 192.168.1.10:8080"}, .negative = Strings{}},
      {.signal = "mitm.user_cas", .positive = Strings{"9a5ba575.0"}, .negative = Strings{}},
      {.signal = "root.fs_paths", .positive = Strings{"/system/bin/su"}, .negative = Strings{}},
      {.signal = "root.mounts", .positive = Strings{"magisk /system/bin tmpfs ro 0 0"}, .negative = Strings{}},
      {
          .signal = "root.rw_mounts",
          .positive = Strings{"/dev/block/dm-0 /system ext4 rw,seclabel 0 0"},
          .negative = Strings{},
      },
      {.signal = "root.selinux_enforcing", .positive = false, .negative = true},
      {.signal = "root.build_props", .positive = Strings{"ro.debuggable=1"}, .negative = Strings{"ro.debuggable=0"}},
      {.signal = "virt.exec_path", .positive = true, .negative = false},
      {.signal = "virt.foreign_images", .positive = Strings{"/var/mobile/host/runtime.dylib"}, .negative = Strings{}},
  };

  for (const SignalCase& signal_case : cases) {
    const std::vector<Detection> expected = {{.signal = std::string(signal_case.signal), .source = "test"}};
    EXPECT_EQ(detect_one(signal_case.signal, signal_case.positive), expected) << signal_case.signal;
    EXPECT_TRUE(detect_one(signal_case.signal, signal_case.negative).empty()) << signal_case.signal;
  }
}

TEST(Panic, detect_forAnInformationalSignal_neverDetectsByValue) {
  const std::vector<std::pair<std::string_view, Value>> cases = {
      {"dbg.exception_ports", std::int64_t{0x1c00}},
      {"id.package", std::string("com.attacker.clone")},
      {"id.uid", std::int64_t{1'010'123}},
      {"id.code_path", std::string("/data/data/com.parallel.intl/lib/librasp.so")},
      {"id.bundle_id", std::string("com.attacker.clone")},
      {"id.team_id", std::string("ATTACKER01")},
      {"id.cdhash", std::string("0123456789abcdef0123456789abcdef01234567")},
      {"integ.text_sha256", std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")},
  };

  for (const auto& [signal, value] : cases) {
    EXPECT_TRUE(detect_one(signal, value).empty()) << signal;
  }
}

TEST(Panic, detect_whenTheSignalIsUnknown_detectsNothing) { EXPECT_TRUE(detect_one("plugin.found", true).empty()); }

TEST(Panic, detect_whenTheValueHasTheWrongType_detectsNothing) {
  EXPECT_TRUE(detect_one("jb.fork_ok", std::int64_t{1}).empty());
  EXPECT_TRUE(detect_one("root.fs_paths", true).empty());
  EXPECT_TRUE(detect_one("dbg.tracer_pid", std::monostate{}).empty());
}

TEST(Panic, detect_whenTheStatusIsNotOk_detectsNothing) {
  for (const Status status : {Status::kUnsupported, Status::kError, Status::kTimeout}) {
    const std::vector<Observation> observations = {
        {.signal = "jb.fork_ok", .source = "fork", .status = status, .value = true},
        {.signal = "dbg.tracer_pid", .source = "proc_status", .status = status, .value = std::int64_t{7}},
    };

    EXPECT_TRUE(detect(observations).empty());
  }
}

TEST(Panic, detect_whenTheTracerPidIsNegative_detectsNothing) {
  EXPECT_TRUE(detect_one("dbg.tracer_pid", std::int64_t{-1}).empty());
}

TEST(Panic, detect_forTheBuildProperties_detectsEachUnsafeOne) {
  for (const std::string_view property : {
           "ro.debuggable=1",
           "ro.secure=0",
           "ro.build.type=eng",
           "ro.build.type=userdebug",
           "ro.build.tags=release-keys,test-keys",
           "ro.boot.verifiedbootstate=orange",
           "ro.boot.verifiedbootstate=red",
           "ro.boot.vbmeta.device_state=unlocked",
           "ro.boot.flash.locked=0",
       }) {
    EXPECT_EQ(detect_one("root.build_props", Strings{"ro.secure=1", std::string(property)}).size(), 1U) << property;
  }
}

TEST(Panic, detect_forAStockDevicesBuildProperties_detectsNothing) {
  const Strings stock = {
      "ro.debuggable=0",
      "ro.secure=1",
      "ro.build.type=user",
      "ro.build.tags=release-keys",
      "ro.boot.verifiedbootstate=green",
      "ro.boot.vbmeta.device_state=locked",
      "ro.boot.flash.locked=1",
  };

  EXPECT_TRUE(detect_one("root.build_props", stock).empty());
  EXPECT_TRUE(detect_one("root.build_props", Strings{"ro.boot.verifiedbootstate=yellow"}).empty());
}

TEST(Panic, detect_whenTheOnlyWritableMountIsTheLegacyRootfs_detectsNothing) {
  EXPECT_TRUE(detect_one("root.rw_mounts", Strings{"rootfs / rootfs rw,seclabel 0 0"}).empty());
  EXPECT_EQ(detect_one("root.rw_mounts",
                       Strings{"rootfs / rootfs rw,seclabel 0 0", "/dev/block/dm-1 /vendor ext4 rw,seclabel 0 0"})
                .size(),
            1U);
}

TEST(Panic, detect_whenTwoSourcesOfOneSignalDisagree_detectsTheDisagreement) {
  const std::vector<Observation> observations = {
      observed("integ.text_sha256", "file", std::string("aa")),
      observed("integ.text_sha256", "memory", std::string("bb")),
  };
  const std::vector<Detection> expected = {{.signal = "integ.text_sha256", .source = "file!=memory"}};

  EXPECT_EQ(detect(observations), expected);
}

TEST(Panic, detect_whenTwoSourcesOfOneSignalAgree_detectsNothing) {
  const std::vector<Observation> observations = {
      observed("integ.text_sha256", "file", std::string("aa")),
      observed("integ.text_sha256", "memory", std::string("aa")),
      observed("id.bundle_id", "CFBundle", std::string("com.example")),
      observed("id.bundle_id", "Info.plist", std::string("com.example")),
  };

  EXPECT_TRUE(detect(observations).empty());
}

TEST(Panic, detect_whenBothJavaDebuggerSourcesSeeNoDebugger_detectsNothing) {
  // The two sources of dbg.java_debugger report the same type, so a clean app is not taken for a disagreement.
  const std::vector<Observation> observations = {
      observed("dbg.java_debugger", "jdwp_threads", false),
      observed("dbg.java_debugger", "debug_api", false),
  };

  EXPECT_TRUE(detect(observations).empty());
}

TEST(Panic, detect_whenTwoSourcesReportValuesOfDifferentTypes_detectsTheDisagreement) {
  // The comparison is by value, type included: sources of one signal must report the same type, or a clean app
  // reads as a disagreement.
  const std::vector<Observation> observations = {
      observed("dbg.java_debugger", "jdwp_threads", Strings{}),
      observed("dbg.java_debugger", "debug_api", false),
  };
  const std::vector<Detection> expected = {{.signal = "dbg.java_debugger", .source = "jdwp_threads!=debug_api"}};

  EXPECT_EQ(detect(observations), expected);
}

TEST(Panic, detect_whenAHookHidesAFileFromOneSource_detectsTheFileAndTheDisagreement) {
  const std::vector<Observation> observations = {
      observed("root.fs_paths", "access", Strings{}),
      observed("root.fs_paths", "stat", Strings{"/system/bin/su"}),
  };
  const std::vector<Detection> expected = {
      {.signal = "root.fs_paths", .source = "stat"},
      {.signal = "root.fs_paths", .source = "access!=stat"},
  };

  EXPECT_EQ(detect(observations), expected);
}

TEST(Panic, detect_whenSeveralSourcesDisagree_detectsTheSignalOnce) {
  const std::vector<Observation> observations = {
      observed("dbg.tracer_pid", "proc_status", std::int64_t{0}),
      observed("dbg.tracer_pid", "syscall", std::int64_t{0}),
      observed("dbg.tracer_pid", "openat", std::int64_t{0}),
      observed("id.package", "proc_cmdline", std::string("com.example")),
      observed("id.package", "syscall", std::string("com.other")),
      observed("id.package", "getauxval", std::string("com.third")),
  };
  const std::vector<Detection> expected = {{.signal = "id.package", .source = "proc_cmdline!=syscall"}};

  EXPECT_EQ(detect(observations), expected);
}

TEST(Panic, detect_whenASourceFailed_comparesOnlyTheOthers) {
  const std::vector<Observation> observations = {
      failed("integ.text_sha256", "file"),
      observed("integ.text_sha256", "memory", std::string("bb")),
  };

  EXPECT_TRUE(detect(observations).empty());
}

TEST(Panic, detect_whenObservationsOfDifferentSignalsDiffer_detectsNothing) {
  const std::vector<Observation> observations = {
      observed("dbg.traced", "sysctl", false),
      observed("hook.frida_port", "connect", false),
      observed("jb.fork_ok", "fork", false),
  };

  EXPECT_TRUE(detect(observations).empty());
}

TEST(Panic, panicDelay_whenCalled_isWithinTheBounds) {
  for (int round = 0; round < 1000; ++round) {
    const milliseconds delay = panic_delay();

    EXPECT_GE(delay, kMinPanicDelay);
    EXPECT_LE(delay, kMaxPanicDelay);
  }
}

TEST(Panic, severePanicDelay_whenCalled_isWithinTheBounds) {
  for (int round = 0; round < 1000; ++round) {
    const milliseconds delay = severe_panic_delay();

    EXPECT_GE(delay, kMinSeverePanicDelay);
    EXPECT_LE(delay, kMaxSeverePanicDelay);
  }
}

TEST(Panic, armPanic_whenArmed_endsTheProcessOnAnotherThreadAfterTheDelay) {
  const int before = end_calls().load();
  const steady_clock::time_point start = steady_clock::now();

  ASSERT_TRUE(arm_panic(record_end, milliseconds{50}));

  EXPECT_EQ(end_calls().load(), before);
  ASSERT_TRUE(wait_for_end_calls(before + 1, milliseconds{50} + kWaitMargin));
  EXPECT_GE(steady_clock::now() - start, milliseconds{50});
}

TEST(Panic, panicOnDetection_whenASevereSignalIsDetected_endsTheProcessWithinTheShortWindow) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {
      observed("id.package", "proc_cmdline", std::string("com.example")),
      observed("dbg.tracer_pid", "proc_status", std::int64_t{4242}),
  };
  const steady_clock::time_point start = steady_clock::now();

  ASSERT_TRUE(panic_on_detection(observations, record_end, {}, CheckPlatform::kAndroid));

  EXPECT_EQ(end_calls().load(), before);
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxSeverePanicDelay + kWaitMargin));
  EXPECT_GE(steady_clock::now() - start, kMinSeverePanicDelay);
}

TEST(Panic, panicOnDetection_whenAnotherSignalIsDetected_armsAPanicThatEndsTheProcessLater) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {
      observed("id.package", "proc_cmdline", std::string("com.example")),
      observed("emu.props", "properties", Strings{"ro.hardware=ranchu"}),
  };
  const steady_clock::time_point start = steady_clock::now();

  ASSERT_TRUE(panic_on_detection(observations, record_end, {}, CheckPlatform::kAndroid));

  EXPECT_EQ(end_calls().load(), before);
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxPanicDelay + kWaitMargin));
  EXPECT_GE(steady_clock::now() - start, kMinPanicDelay);
}

TEST(Panic, panicOnDetection_whenNothingIsDetected_armsNothing) {
  const std::vector<Observation> observations = {
      observed("id.package", "proc_cmdline", std::string("com.example")),
      observed("dbg.tracer_pid", "proc_status", std::int64_t{0}),
      unsupported("jb.fork_ok", "fork"),
      failed("root.fs_paths", "stat"),
  };

  EXPECT_FALSE(panic_on_detection(observations, record_end, {}, CheckPlatform::kAndroid));
}

TEST(Panic, panicOnDetection_whenMitmReportsOnly_neverArmsForAVpnOrDisagreementOnEitherPlatform) {
  const std::vector<Observation> observations = {
      observed("mitm.tunnels", "getifaddrs", Strings{"tun0"}),
      observed("mitm.tunnels", "other", Strings{}),
      observed("mitm.proxies", "settings", Strings{"proxy"}),
      observed("mitm.user_cas", "store", Strings{"certificate"}),
  };
  EXPECT_FALSE(panic_on_detection(observations, record_end,
                                  {.build_id = {}, .checks_mask = 0xFF, .report_only_mask = 1U << 4},
                                  CheckPlatform::kAndroid));
  EXPECT_FALSE(panic_on_detection(observations, record_end,
                                  {.build_id = {}, .checks_mask = 0xFF, .report_only_mask = 1U << 7},
                                  CheckPlatform::kIos));
  EXPECT_EQ(detect(observations).size(), 4U);
}

TEST(Panic, panicOnDetection_whenAKnownSignalDisagrees_honorsItsGroupOnEverySupportedPlatform) {
  // The bit numbers follow the packer and each platform's monitoring dispatch.
  const std::vector<std::pair<unsigned, Strings>> android = {
      {0, {"root.fs_paths", "root.mounts", "root.rw_mounts", "root.selinux_enforcing", "root.build_props"}},
      {1, {"dbg.tracer_pid", "dbg.java_debugger"}},
      {2, {"hook.maps_hits", "hook.rwx_regions", "hook.threads", "hook.foreign_libs", "hook.inline"}},
      {3, {"integ.text_sha256", "integ.monitor_alive"}},
      {4, {"mitm.tunnels", "mitm.user_cas"}},
      {5, {"id.package", "id.uid", "id.code_path", "id.debuggable", "sig.cert_sha256"}},
      {6, {"emu.props"}},
  };
  const std::vector<std::pair<unsigned, Strings>> ios = {
      {0, {"jb.fs_paths", "jb.sandbox_escape", "jb.fork_ok"}},
      {1, {"dbg.traced", "dbg.parent", "dbg.exception_ports"}},
      {2, {"hook.maps_hits", "hook.rwx_regions", "hook.dyld_env", "hook.frida_port", "hook.inline"}},
      {3, {"id.bundle_id", "id.team_id", "id.cdhash", "id.debuggable"}},
      {4, {"cs.valid", "cs.debugged", "cs.get_task_allow", "cs.library_validation"}},
      {5, {"emu.simulator", "hw.machine"}},
      {6, {"virt.exec_path", "virt.foreign_images"}},
      {7, {"mitm.tunnels", "mitm.proxies", "mitm.user_cas"}},
  };
  const auto check_groups = [](const auto& groups, CheckPlatform platform) {
    for (const auto& [bit, signals] : groups) {
      for (const std::string& signal : signals) {
        const std::vector<Observation> observations = {
            observed(signal, "first", std::string("a")),
            observed(signal, "second", std::string("b")),
        };
        ASSERT_FALSE(detect(observations).empty()) << signal;
        EXPECT_FALSE(panic_on_detection(
            observations, record_end,
            {.build_id = {}, .checks_mask = 0xFF, .report_only_mask = std::uint64_t{1} << bit}, platform))
            << signal;
      }
    }
  };
  check_groups(android, CheckPlatform::kAndroid);
  check_groups(ios, CheckPlatform::kIos);
}

TEST(Panic, panicOnDetection_whenOnlyTheSevereGroupReports_usesTheLongDelayForTheBlockingGroup) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {
      observed("dbg.tracer_pid", "proc_status", std::int64_t{42}),
      observed("mitm.tunnels", "getifaddrs", Strings{"tun0"}),
  };
  const steady_clock::time_point start = steady_clock::now();
  ASSERT_TRUE(panic_on_detection(observations, record_end,
                                 {.build_id = {}, .checks_mask = 0xFF, .report_only_mask = 1U << 1},
                                 CheckPlatform::kAndroid));
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxPanicDelay + kWaitMargin));
  EXPECT_GE(steady_clock::now() - start, kMinPanicDelay);
}

TEST(Panic, panicOnDetection_whenTheGroupIsUnknown_blocksEvenWithEveryReportBitSet) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {
      observed("unknown.signal", "first", true),
      observed("unknown.signal", "second", false),
  };
  ASSERT_TRUE(panic_on_detection(observations, record_end,
                                 {.build_id = {}, .checks_mask = 0xFF, .report_only_mask = ~std::uint64_t{0}},
                                 CheckPlatform::kIos));
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxPanicDelay + kWaitMargin));
}

TEST(Panic, panicOnDetection_whenDeviceStateChecksAreOff_armsNothingInEitherPlatformOrder) {
  const std::vector<Observation> root = {observed("root.fs_paths", "access", Strings{"su"})};
  const std::vector<Observation> jailbreak = {observed("jb.fs_paths", "access", Strings{"/var/jb"})};
  // Root is Android-only; jailbreak is its iOS counterpart. Bit zero belongs to each platform's device check.
  const Config mask{.build_id = {}, .checks_mask = 1U << 1};
  const Config list{.build_id = {}, .checks = Strings{"debugger"}};
  for (const Config& config : {mask, list}) {
    EXPECT_FALSE(panic_on_detection(root, record_end, config, CheckPlatform::kAndroid));
    EXPECT_FALSE(panic_on_detection(jailbreak, record_end, config, CheckPlatform::kIos));
  }
}

TEST(Panic, panicOnDetection_whenTheEnabledMaskIsPresent_usesItInsteadOfTheList) {
  const std::vector<Observation> root = {observed("root.fs_paths", "access", Strings{"su"})};
  const Config config{.build_id = {}, .checks = Strings{"root"}, .checks_mask = 0};
  EXPECT_FALSE(panic_on_detection(root, record_end, config, CheckPlatform::kAndroid));
}

TEST(Panic, panicOnDetection_whenAnOffGroupDisagrees_armsNothing) {
  const std::vector<Observation> observations = {
      observed("root.fs_paths", "access", Strings{"su"}),
      observed("root.fs_paths", "stat", Strings{}),
  };
  ASSERT_FALSE(detect(observations).empty());
  EXPECT_FALSE(
      panic_on_detection(observations, record_end, {.build_id = {}, .checks_mask = 0}, CheckPlatform::kAndroid));
}

TEST(Panic, panicOnDetection_whenTheConfigHasNeitherMaskNorList_keepsBlockingDeviceDetections) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {observed("root.fs_paths", "access", Strings{"su"})};
  ASSERT_TRUE(panic_on_detection(observations, record_end, {}, CheckPlatform::kAndroid));
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxPanicDelay + kWaitMargin));
}

TEST(Panic, panicOnDetection_whenOnlyTheSevereGroupIsOff_usesTheBlockingGroupsLongDelay) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {
      observed("dbg.tracer_pid", "proc_status", std::int64_t{42}),
      observed("root.fs_paths", "access", Strings{"su"}),
  };
  const steady_clock::time_point start = steady_clock::now();
  ASSERT_TRUE(
      panic_on_detection(observations, record_end, {.build_id = {}, .checks_mask = 1}, CheckPlatform::kAndroid));
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxPanicDelay + kWaitMargin));
  EXPECT_GE(steady_clock::now() - start, kMinPanicDelay);
}

TEST(Panic, panicOnDetection_whenAMonitoringHeartbeatIsOff_armsNothing) {
  const std::vector<Observation> observations = {observed("integ.monitor_alive", "heartbeat", false)};
  EXPECT_FALSE(
      panic_on_detection(observations, record_end, {.build_id = {}, .checks_mask = 0}, CheckPlatform::kAndroid));
}

TEST(Panic, panicOnDetection_whenOnlyTheReportMaskIsReadable_keepsBlocking) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {observed("root.fs_paths", "access", Strings{"su"})};
  ASSERT_TRUE(
      panic_on_detection(observations, record_end, {.build_id = {}, .report_only_mask = 1}, CheckPlatform::kAndroid));
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxPanicDelay + kWaitMargin));
}

TEST(Panic, panicOnDetection_whenTheGroupHasNoPlatformBit_keepsBlocking) {
  const int before = end_calls().load();
  const std::vector<Observation> observations = {observed("root.fs_paths", "access", Strings{"su"})};
  const Config config{.build_id = {}, .checks_mask = 0, .report_only_mask = 0xFF};
  ASSERT_TRUE(panic_on_detection(observations, record_end, config, CheckPlatform::kIos));
  ASSERT_TRUE(wait_for_end_calls(before + 1, kMaxPanicDelay + kWaitMargin));
}

}  // namespace
}  // namespace rasp
