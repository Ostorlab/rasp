/// Tests for the plugin host, with fake plugins built in the test process: the plugin list, the checks on a plugin's
/// table, the order of a pass, what emit copies and refuses, and what on_pass receives.

#include "rasp/plugins/host.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/version.h"

extern "C" {
/// The table of the plugin written in C, in c_plugin.c.
///
/// @return The table.
const rasp_plugin* rasp_test_c_plugin();
/// How many observations the C plugin's on_pass last saw.
///
/// @return The count.
std::size_t rasp_test_c_plugin_seen();
}

namespace rasp::plugins {
namespace {

/// The C string of `text`.
///
/// @param text Text that outlives the result.
/// @return The C string that points at it.
[[nodiscard]] rasp_string c_text(std::string_view text) { return {.data = text.data(), .size = text.size()}; }

/// The `run` function of a check.
using CheckRun = void (*)(void* state, rasp_emit emit, void* emitter);

/// A fake plugin: its table, what its checks emit, and what its on_pass received. It must not move once `table` was
/// called for it, because the table points back at it.
struct FakePlugin {
  /// The plugin's name, used for its table and its signals.
  std::string name;
  /// What the `script` check emits, in order.
  std::vector<Observation> script;
  /// C observations the `raw` check emits as they are, to hand over invalid fields.
  std::vector<rasp_observation> raw;
  /// What every call of on_pass received, one list per pass.
  std::vector<std::vector<Observation>> passes;
  /// The emit function the last check received, so a test can call it late.
  rasp_emit saved_emit = nullptr;
  /// The emitter the last check received, so a test can call it late.
  void* saved_emitter = nullptr;
  /// Whether on_pass calls the saved emit, after the checks are done.
  bool emit_in_on_pass = false;
  /// The checks of the table.
  std::vector<rasp_check> checks;
  /// The table.
  rasp_plugin plugin{};
};

/// Makes a fake plugin with no table yet.
///
/// @param name The plugin's name.
/// @param script What its `script` check emits.
/// @return The fake plugin.
[[nodiscard]] FakePlugin fake_plugin(std::string name, std::vector<Observation> script = {}) {
  return {
      .name = std::move(name),
      .script = std::move(script),
      .raw = {},
      .passes = {},
      .saved_emit = nullptr,
      .saved_emitter = nullptr,
      .emit_in_on_pass = false,
      .checks = {},
      .plugin = {},
  };
}

/// The check that emits every observation of the fake's `script`, through a C view of them.
///
/// @param state The FakePlugin.
/// @param emit The function that adds an observation to the pass.
/// @param emitter The first argument to pass to `emit`.
void emit_script(void* state, rasp_emit emit, void* emitter) {
  auto* const fake = static_cast<FakePlugin*>(state);
  fake->saved_emit = emit;
  fake->saved_emitter = emitter;
  const ObservationView view(fake->script);
  for (const rasp_observation& record : view.records()) {
    emit(emitter, &record);
  }
}

/// The check that emits every observation of the fake's `raw`, as it is.
///
/// @param state The FakePlugin.
/// @param emit The function that adds an observation to the pass.
/// @param emitter The first argument to pass to `emit`.
void emit_raw(void* state, rasp_emit emit, void* emitter) {
  for (const rasp_observation& record : static_cast<FakePlugin*>(state)->raw) {
    emit(emitter, &record);
  }
}

/// The check that emits `<name>.second`, true.
///
/// @param state The FakePlugin.
/// @param emit The function that adds an observation to the pass.
/// @param emitter The first argument to pass to `emit`.
void emit_second(void* state, rasp_emit emit, void* emitter) {
  const std::string signal = static_cast<FakePlugin*>(state)->name + ".second";
  const rasp_observation record{
      .signal = c_text(signal),
      .source = c_text("test"),
      .status = RASP_STATUS_OK,
      .value = {.kind = RASP_VALUE_BOOL, .boolean = true},
  };
  emit(emitter, &record);
}

/// The on_pass: copies every observation of the pass, and calls the saved emit when the fake asks for it.
///
/// @param state The FakePlugin.
/// @param observations The observations of the pass.
/// @param count The number of observations.
void record_pass(void* state, const rasp_observation* observations, std::size_t count) {
  auto* const fake = static_cast<FakePlugin*>(state);
  std::vector<Observation> pass;
  for (const rasp_observation& record : std::span(observations, count)) {
    const std::optional<Observation> copy = copy_observation(record);
    if (copy.has_value()) {
      pass.push_back(*copy);
    }
  }
  fake->passes.push_back(pass);
  if (fake->emit_in_on_pass && fake->saved_emit != nullptr) {
    const std::string signal = fake->name + ".late";
    const rasp_observation late{
        .signal = c_text(signal),
        .source = c_text("test"),
        .status = RASP_STATUS_OK,
        .value = {.kind = RASP_VALUE_NONE, .integer = 0},
    };
    fake->saved_emit(fake->saved_emitter, &late);
  }
}

/// Builds the fake's table with the given checks and an on_pass that records each pass.
///
/// @param fake The fake plugin, which must not move afterward.
/// @param runs The `run` function of each check, in order.
/// @return The table, valid while `fake` lives.
[[nodiscard]] const rasp_plugin* table(FakePlugin& fake, std::span<const CheckRun> runs) {
  fake.checks.clear();
  for (const CheckRun run : runs) {
    fake.checks.push_back({.name = c_text("check"), .run = run});
  }
  fake.plugin = {
      .size = sizeof(rasp_plugin),
      .api_version = RASP_PLUGIN_API_VERSION,
      .name = c_text(fake.name),
      .version = c_text("1.0"),
      .state = &fake,
      .checks = fake.checks.empty() ? nullptr : fake.checks.data(),
      .check_count = fake.checks.size(),
      .on_pass = record_pass,
  };
  return &fake.plugin;
}

/// The run functions of a plugin with only the `script` check.
constexpr std::array<CheckRun, 1> kScript{emit_script};
/// The run functions of a plugin with only the `raw` check.
constexpr std::array<CheckRun, 1> kRaw{emit_raw};

/// The signals of `observations`, in order.
///
/// @param observations The observations.
/// @return Their signals.
[[nodiscard]] std::vector<std::string> signals(const std::vector<Observation>& observations) {
  std::vector<std::string> names;
  names.reserve(observations.size());
  for (const Observation& observation : observations) {
    names.push_back(observation.signal);
  }
  return names;
}

/// The observations a plugin named `name` added to `pass`: those whose source or signal names it, past the built-ins.
///
/// @param pass The observations of a pass.
/// @param prefix The prefix of the plugin's signals, such as `alpha.`.
/// @return The observations whose signal starts with `prefix` or is `plugin.signal`.
[[nodiscard]] std::vector<Observation> emitted(const std::vector<Observation>& pass, std::string_view prefix) {
  std::vector<Observation> found;
  for (const Observation& observation : pass) {
    if (observation.signal.starts_with(prefix) || observation.signal == kRefusedSignal) {
      found.push_back(observation);
    }
  }
  return found;
}

/// The observation that replaces one the runtime refused from the plugin `name`.
///
/// @param name The plugin's name.
/// @return A `plugin.signal` error with `name` as source.
[[nodiscard]] Observation refused(std::string_view name) { return failed(kRefusedSignal, name); }

TEST(PluginHost, runPass_whenPluginsAreListed_runsBuiltInsThenLoadsThenEachPluginsChecksInOrder) {
  FakePlugin alpha = fake_plugin("alpha", {observed("alpha.first", "test", true)});
  FakePlugin beta = fake_plugin("beta", {observed("beta.first", "test", true)});
  constexpr std::array<CheckRun, 2> kTwo{emit_script, emit_second};
  const std::array<Listed, 2> listed{
      {{.name = "alpha", .table = table(alpha, kTwo)}, {.name = "beta", .table = table(beta, kTwo)}},
  };
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({observed("jb.fork_ok", "fork", false)});

  EXPECT_EQ(signals(pass), (std::vector<std::string>{"jb.fork_ok", "plugin.load", "plugin.load", "alpha.first",
                                                     "alpha.second", "beta.first", "beta.second"}));
  EXPECT_EQ(pass[1], observed("plugin.load", "alpha", Value{}));
  EXPECT_EQ(pass[2], observed("plugin.load", "beta", Value{}));
}

TEST(PluginHost, runPass_whenChecksAreDone_givesEveryPluginEveryObservationOfThePass) {
  FakePlugin alpha = fake_plugin("alpha", {observed("alpha.first", "test", std::int64_t{7})});
  FakePlugin beta = fake_plugin(
      "beta", {observed("beta.first", "test", std::vector<std::string>{"x", "yz"}), unsupported("beta.none", "test")});
  const std::array<Listed, 2> listed{
      {{.name = "alpha", .table = table(alpha, kScript)}, {.name = "beta", .table = table(beta, kScript)}},
  };
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({observed("jb.fs_paths", "stat", std::string("/bin/sh"))});

  ASSERT_EQ(alpha.passes.size(), 1U);
  EXPECT_EQ(alpha.passes[0], pass);
  ASSERT_EQ(beta.passes.size(), 1U);
  EXPECT_EQ(beta.passes[0], pass);
}

TEST(PluginHost, runPass_whenCalledAgain_runsTheChecksAndOnPassAgain) {
  FakePlugin alpha = fake_plugin("alpha", {observed("alpha.first", "test", true)});
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kScript)}}};
  Host host(listed);

  const std::vector<Observation> first = host.run_pass({});
  const std::vector<Observation> second = host.run_pass({});

  EXPECT_EQ(first, second);
  EXPECT_EQ(alpha.passes.size(), 2U);
}

TEST(PluginHost, runPass_whenNoPluginIsListed_returnsTheBuiltInObservations) {
  Host host(std::span<const Listed>{});
  const std::vector<Observation> builtin{observed("jb.fork_ok", "fork", false)};

  EXPECT_EQ(host.run_pass(builtin), builtin);
}

TEST(PluginHost, emit_whenTheCheckChangesItsObservationAfterward_keepsTheCopy) {
  FakePlugin alpha = fake_plugin("alpha");
  std::string signal = "alpha.copy";
  std::string source = "test";
  std::string item = "first";
  const std::array<rasp_string, 1> items{c_text(item)};
  alpha.raw.push_back({
      .signal = c_text(signal),
      .source = c_text(source),
      .status = RASP_STATUS_OK,
      .value = {.kind = RASP_VALUE_STRING_LIST, .list = {.items = items.data(), .count = items.size()}},
  });
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kRaw)}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({});
  signal[0] = 'X';
  source[0] = 'X';
  item[0] = 'X';

  EXPECT_EQ(pass.back(), observed("alpha.copy", "test", std::vector<std::string>{"first"}));
}

TEST(PluginHost, emit_whenTheSignalLacksThePluginsPrefix_replacesItWithAnError) {
  FakePlugin alpha = fake_plugin("alpha", {
                                              observed("beta.x", "test", true),
                                              observed("alpha.", "test", true),
                                              observed("alphabet.x", "test", true),
                                              observed("alpha", "test", true),
                                              observed("alpha.kept", "test", true),
                                          });
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kScript)}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({});

  EXPECT_EQ(emitted(pass, "alpha."),
            (std::vector<Observation>{refused("alpha"), refused("alpha"), refused("alpha"), refused("alpha"),
                                      observed("alpha.kept", "test", true)}));
}

TEST(PluginHost, emit_whenAFieldIsInvalid_replacesTheObservationWithAnError) {
  FakePlugin alpha = fake_plugin("alpha");
  const std::string long_text(kMaxTextSize + 1, 'a');
  const std::string long_value(kMaxValueSize + 1, 'a');
  const std::vector<rasp_string> many_items(kMaxListItems + 1, c_text("x"));
  const rasp_observation valid{
      .signal = c_text("alpha.valid"),
      .source = c_text("test"),
      .status = RASP_STATUS_OK,
      .value = {.kind = RASP_VALUE_NONE, .integer = 0},
  };
  rasp_observation null_signal = valid;
  null_signal.signal = {.data = nullptr, .size = 3};
  rasp_observation long_source = valid;
  long_source.source = c_text(long_text);
  rasp_observation unknown_status = valid;
  const unsigned int bad_status = 9;
  std::memcpy(&unknown_status.status, &bad_status, sizeof(bad_status));
  rasp_observation unknown_kind = valid;
  const unsigned int bad_kind = 9;
  std::memcpy(&unknown_kind.value.kind, &bad_kind, sizeof(bad_kind));
  rasp_observation long_string = valid;
  long_string.value = {.kind = RASP_VALUE_STRING, .string = c_text(long_value)};
  rasp_observation null_items = valid;
  null_items.value = {.kind = RASP_VALUE_STRING_LIST, .list = {.items = nullptr, .count = 2}};
  rasp_observation too_many_items = valid;
  too_many_items.value = {
      .kind = RASP_VALUE_STRING_LIST,
      .list = {.items = many_items.data(), .count = many_items.size()},
  };
  alpha.raw = {null_signal, long_source, unknown_status, unknown_kind, long_string, null_items, too_many_items, valid};
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kRaw)}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({});

  EXPECT_EQ(emitted(pass, "alpha."),
            (std::vector<Observation>{refused("alpha"), refused("alpha"), refused("alpha"), refused("alpha"),
                                      refused("alpha"), refused("alpha"), refused("alpha"),
                                      observed("alpha.valid", "test", Value{})}));
}

TEST(PluginHost, emit_whenTheObservationIsNull_replacesItWithAnError) {
  FakePlugin alpha = fake_plugin("alpha");
  constexpr std::array<CheckRun, 1> kNull{
      [](void* /*state*/, rasp_emit emit, void* emitter) { emit(emitter, nullptr); },
  };
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kNull)}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({});

  EXPECT_EQ(pass.back(), refused("alpha"));
}

TEST(PluginHost, emit_whenThePluginEmitsTooManyObservations_keepsTheFirstOnes) {
  FakePlugin alpha =
      fake_plugin("alpha", std::vector<Observation>(kMaxObservations + 10, observed("alpha.x", "t", true)));
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kScript)}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({});

  EXPECT_EQ(emitted(pass, "alpha."), std::vector<Observation>(kMaxObservations, observed("alpha.x", "t", true)));
}

TEST(PluginHost, emit_whenThePluginEmitsTooManyBytes_refusesTheObservationsPastTheBudget) {
  const std::string big(kMaxValueSize, 'a');
  const std::size_t fitting = kMaxPassBytes / (big.size() + std::string_view("alpha.big").size() + 1);
  FakePlugin alpha = fake_plugin("alpha", std::vector<Observation>(fitting + 2, observed("alpha.big", "t", big)));
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kScript)}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({});

  std::vector<Observation> expected(fitting, observed("alpha.big", "t", big));
  expected.push_back(refused("alpha"));
  expected.push_back(refused("alpha"));
  EXPECT_EQ(emitted(pass, "alpha."), expected);
}

TEST(PluginHost, emit_whenCalledAfterTheCheckReturned_addsNothing) {
  FakePlugin alpha = fake_plugin("alpha", {observed("alpha.first", "test", true)});
  alpha.emit_in_on_pass = true;
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = table(alpha, kScript)}}};
  Host host(listed);

  const std::vector<Observation> first = host.run_pass({});
  const std::vector<Observation> second = host.run_pass({});

  EXPECT_EQ(signals(first), (std::vector<std::string>{"plugin.load", "alpha.first"}));
  EXPECT_EQ(first, second);
}

TEST(PluginHost, host_whenInitReturnedNull_reportsTheLoadAsAnError) {
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = nullptr}}};
  Host host(listed);

  EXPECT_EQ(host.run_pass({}), std::vector<Observation>{failed("plugin.load", "alpha")});
}

TEST(PluginHost, host_whenTheApiVersionIsOutOfRange_refusesThePlugin) {
  FakePlugin old_version = fake_plugin("alpha", {observed("alpha.first", "test", true)});
  FakePlugin new_version = fake_plugin("beta", {observed("beta.first", "test", true)});
  const rasp_plugin* const old_table = table(old_version, kScript);
  const rasp_plugin* const new_table = table(new_version, kScript);
  old_version.plugin.api_version = 0;
  new_version.plugin.api_version = RASP_PLUGIN_API_VERSION + 1;
  const std::array<Listed, 2> listed{{{.name = "alpha", .table = old_table}, {.name = "beta", .table = new_table}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({});

  EXPECT_EQ(pass, (std::vector<Observation>{failed("plugin.load", "alpha"), failed("plugin.load", "beta")}));
  EXPECT_TRUE(old_version.passes.empty());
  EXPECT_TRUE(new_version.passes.empty());
}

TEST(PluginHost, host_whenTheSizeDoesNotCoverVersion1_refusesThePlugin) {
  FakePlugin alpha = fake_plugin("alpha", {observed("alpha.first", "test", true)});
  const rasp_plugin* const alpha_table = table(alpha, kScript);
  alpha.plugin.size = sizeof(rasp_plugin) - 1;
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = alpha_table}}};
  Host host(listed);

  EXPECT_EQ(host.run_pass({}), std::vector<Observation>{failed("plugin.load", "alpha")});
}

TEST(PluginHost, host_whenTheTableIsLargerThanVersion1_readsTheVersion1Fields) {
  struct Later {
    rasp_plugin v1;
    std::uint64_t added;
  };
  FakePlugin alpha = fake_plugin("alpha", {observed("alpha.first", "test", true)});
  Later later{.v1 = *table(alpha, kScript), .added = 1};
  later.v1.size = sizeof(Later);
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = &later.v1}}};
  Host host(listed);

  EXPECT_EQ(signals(host.run_pass({})), (std::vector<std::string>{"plugin.load", "alpha.first"}));
}

TEST(PluginHost, host_whenTheTablesNameDiffersFromTheListedName_refusesThePlugin) {
  FakePlugin alpha = fake_plugin("alpha");
  const std::array<Listed, 2> listed{
      {{.name = "beta", .table = table(alpha, kScript)}, {.name = "Alpha", .table = table(alpha, kScript)}},
  };
  Host host(listed);

  EXPECT_EQ(host.run_pass({}),
            (std::vector<Observation>{failed("plugin.load", "beta"), failed("plugin.load", "Alpha")}));
}

TEST(PluginHost, host_whenATableFieldIsInvalid_refusesThePlugin) {
  std::vector<FakePlugin> fakes;
  fakes.reserve(5);
  for (std::size_t index = 0; index < 5; ++index) {
    fakes.push_back(fake_plugin("alpha"));
  }
  for (FakePlugin& fake : fakes) {
    static_cast<void>(table(fake, kScript));
  }
  fakes[0].plugin.version = {.data = nullptr, .size = 1};
  fakes[1].checks[0].name = {.data = nullptr, .size = 1};
  fakes[2].checks[0].run = nullptr;
  fakes[3].plugin.checks = nullptr;
  fakes[4].plugin.check_count = kMaxChecks + 1;
  for (const FakePlugin& fake : fakes) {
    const std::array<Listed, 1> listed{{{.name = "alpha", .table = &fake.plugin}}};
    Host host(listed);

    EXPECT_EQ(host.run_pass({}), std::vector<Observation>{failed("plugin.load", "alpha")});
  }
}

TEST(PluginHost, host_whenOnPassIsNull_runsTheChecks) {
  FakePlugin alpha = fake_plugin("alpha", {observed("alpha.first", "test", true)});
  const rasp_plugin* const alpha_table = table(alpha, kScript);
  alpha.plugin.on_pass = nullptr;
  const std::array<Listed, 1> listed{{{.name = "alpha", .table = alpha_table}}};
  Host host(listed);

  EXPECT_EQ(signals(host.run_pass({})), (std::vector<std::string>{"plugin.load", "alpha.first"}));
  EXPECT_TRUE(alpha.passes.empty());
}

TEST(PluginHost, host_whenThePluginIsWrittenInC_runsItsCheckAndGivesItThePass) {
  const std::array<Listed, 1> listed{{{.name = "c", .table = rasp_test_c_plugin()}}};
  Host host(listed);

  const std::vector<Observation> pass = host.run_pass({observed("jb.fork_ok", "fork", false)});

  EXPECT_EQ(pass,
            (std::vector<Observation>{observed("jb.fork_ok", "fork", false), observed("plugin.load", "c", Value{}),
                                      observed("c.list", "c", std::vector<std::string>{"a", "bc"})}));
  EXPECT_EQ(rasp_test_c_plugin_seen(), pass.size());
}

TEST(PluginList, validName_whenTheNameMatchesThePattern_isTrue) {
  EXPECT_TRUE(valid_name("a"));
  EXPECT_TRUE(valid_name("example"));
  EXPECT_TRUE(valid_name("my_plugin2"));
  EXPECT_TRUE(valid_name(std::string(kMaxNameSize, 'a')));
}

TEST(PluginList, validName_whenTheNameBreaksThePattern_isFalse) {
  EXPECT_FALSE(valid_name(""));
  EXPECT_FALSE(valid_name("2plugin"));
  EXPECT_FALSE(valid_name("_plugin"));
  EXPECT_FALSE(valid_name("Plugin"));
  EXPECT_FALSE(valid_name("my-plugin"));
  EXPECT_FALSE(valid_name("../plugin"));
  EXPECT_FALSE(valid_name(std::string(kMaxNameSize + 1, 'a')));
}

TEST(PluginList, parseList_whenLinesEndInLineFeedsOrCarriageReturns_returnsTheNamesInOrder) {
  EXPECT_EQ(parse_list("beta\nalpha\r\n\nBad Name\ngamma"),
            (std::vector<std::string>{"beta", "alpha", "Bad Name", "gamma"}));
}

TEST(PluginList, parseList_whenTheListHasTooManyNames_keepsTheFirstOnes) {
  std::string text;
  for (std::size_t index = 0; index < kMaxPlugins + 3; ++index) {
    text += "p" + std::to_string(index) + "\n";
  }

  const std::vector<std::string> names = parse_list(text);

  ASSERT_EQ(names.size(), kMaxPlugins);
  EXPECT_EQ(names.back(), "p" + std::to_string(kMaxPlugins - 1));
}

TEST(PluginList, parseList_whenTheListIsEmpty_returnsNoName) { EXPECT_TRUE(parse_list("\n\n").empty()); }

TEST(PluginHostInfo, hostInfo_whenCalled_describesThisRuntimeAndThePlatform) {
  const std::string config("a\0b", 3);
  int vm = 0;

  const rasp_host host = host_info("android", config, &vm);

  EXPECT_EQ(host.size, sizeof(rasp_host));
  EXPECT_EQ(host.api_version, RASP_PLUGIN_API_VERSION);
  EXPECT_EQ(std::string_view(host.runtime_version.data, host.runtime_version.size), kRuntimeVersion);
  EXPECT_EQ(std::string_view(host.platform.data, host.platform.size), "android");
  EXPECT_EQ(std::string_view(host.config.data, host.config.size), config);
  EXPECT_EQ(host.java_vm, &vm);
}

TEST(PluginObservationView, records_whenCopiedBack_giveTheSameObservations) {
  const std::vector<Observation> observations{
      observed("a.none", "s", Value{}),
      observed("a.bool", "s", true),
      observed("a.int", "s", std::int64_t{-5}),
      observed("a.string", "s", std::string("text")),
      observed("a.list", "s", std::vector<std::string>{"x", "", "yz"}),
      observed("a.empty", "s", std::vector<std::string>{}),
      unsupported("a.unsupported", "s"),
      failed("a.failed", "s"),
      Observation{.signal = "a.timeout", .source = "s", .status = Status::kTimeout, .value = {}},
  };

  const ObservationView view(observations);

  std::vector<Observation> copies;
  for (const rasp_observation& record : view.records()) {
    const std::optional<Observation> copy = copy_observation(record);
    ASSERT_TRUE(copy.has_value());
    copies.push_back(*copy);
  }
  EXPECT_EQ(copies, observations);
}

}  // namespace
}  // namespace rasp::plugins
