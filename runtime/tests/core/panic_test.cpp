/// Tests for detect.

#include "rasp/panic.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/observation.h"

namespace rasp {
namespace {

using Strings = std::vector<std::string>;

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

}  // namespace
}  // namespace rasp
