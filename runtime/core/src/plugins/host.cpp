/// The plugin host: the plugin list, the checks on what plugins hand over, the conversions between the runtime's
/// observations and the C ones, and the pass.

#include "rasp/plugins/host.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/version.h"

namespace rasp::plugins {

static_assert(static_cast<int>(RASP_STATUS_OK) == static_cast<int>(Status::kOk));
static_assert(static_cast<int>(RASP_STATUS_UNSUPPORTED) == static_cast<int>(Status::kUnsupported));
static_assert(static_cast<int>(RASP_STATUS_ERROR) == static_cast<int>(Status::kError));
static_assert(static_cast<int>(RASP_STATUS_TIMEOUT) == static_cast<int>(Status::kTimeout));

namespace {

/// The size of a version 1 rasp_plugin: up to the end of `on_pass`, its last field.
constexpr std::size_t kPluginSizeV1 = offsetof(rasp_plugin, on_pass) + sizeof(rasp_plugin::on_pass);

/// The raw integer type that holds a rasp_status.
using StatusBits = std::underlying_type_t<rasp_status>;
/// The raw integer type that holds a rasp_value_kind.
using KindBits = std::underlying_type_t<rasp_value_kind>;

/// Whether `c` is a lowercase ASCII letter.
///
/// @param c The character.
/// @return `true` for `a` to `z`.
[[nodiscard]] constexpr bool lower(char c) { return c >= 'a' && c <= 'z'; }

/// Whether `c` is an ASCII digit.
///
/// @param c The character.
/// @return `true` for `0` to `9`.
[[nodiscard]] constexpr bool digit(char c) { return c >= '0' && c <= '9'; }

/// A view of the bytes of a plugin's string, when it is valid.
///
/// @param text The plugin's string.
/// @param limit The largest size accepted, in bytes.
/// @return The bytes. Nothing when `data` is null with a size above 0, or the size is over `limit`.
[[nodiscard]] std::optional<std::string_view> view(const rasp_string& text, std::size_t limit) {
  if (text.size > limit || (text.data == nullptr && text.size > 0)) {
    return std::nullopt;
  }
  if (text.size == 0) {
    return std::string_view{};
  }
  return std::string_view(text.data, text.size);
}

/// A copy of a plugin's string, when it is valid.
///
/// @param text The plugin's string.
/// @param limit The largest size accepted, in bytes.
/// @return The copy. Nothing when `data` is null with a size above 0, or the size is over `limit`.
[[nodiscard]] std::optional<std::string> copy(const rasp_string& text, std::size_t limit) {
  const std::optional<std::string_view> bytes = view(text, limit);
  if (!bytes.has_value()) {
    return std::nullopt;
  }
  return std::string(*bytes);
}

/// The C string that points at the bytes of `text`.
///
/// @param text The text to point at. It must outlive the result.
/// @return The C string.
[[nodiscard]] rasp_string c_string(std::string_view text) { return {.data = text.data(), .size = text.size()}; }

/// A copy of a plugin's list of strings, when it is valid.
///
/// @param list The plugin's list.
/// @return The copy. Nothing when `items` is null with a count above 0, the count is over kMaxListItems, or an item
/// is invalid.
[[nodiscard]] std::optional<std::vector<std::string>> copy_list(const rasp_string_list& list) {
  if (list.count > kMaxListItems || (list.items == nullptr && list.count > 0)) {
    return std::nullopt;
  }
  std::vector<std::string> items;
  if (list.count == 0) {
    return items;
  }
  items.reserve(list.count);
  for (const rasp_string& item : std::span(list.items, list.count)) {
    std::optional<std::string> text = copy(item, kMaxValueSize);
    if (!text.has_value()) {
      return std::nullopt;
    }
    items.push_back(std::move(*text));
  }
  return items;
}

/// A copy of a plugin's value, when it is valid.
///
/// The kind and the boolean are read as raw bytes, so a value a plugin set out of range is refused, not read.
///
/// @param value The plugin's value.
/// @return The copy. Nothing when the kind is unknown or the member it names is invalid.
[[nodiscard]] std::optional<Value> copy_value(const rasp_value& value) {
  KindBits kind = 0;
  std::memcpy(&kind, &value.kind, sizeof(kind));
  switch (kind) {
    case RASP_VALUE_NONE:
      return Value{};
    case RASP_VALUE_BOOL: {
      unsigned char byte = 0;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access): the C value is a tagged union; `kind` names this member.
      std::memcpy(&byte, &value.boolean, sizeof(byte));
      return Value{byte != 0};
    }
    case RASP_VALUE_INT:
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access): the C value is a tagged union; `kind` names this member.
      return Value{std::int64_t{value.integer}};
    case RASP_VALUE_STRING: {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access): the C value is a tagged union; `kind` names this member.
      std::optional<std::string> text = copy(value.string, kMaxValueSize);
      if (!text.has_value()) {
        return std::nullopt;
      }
      return Value{std::move(*text)};
    }
    case RASP_VALUE_STRING_LIST: {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access): the C value is a tagged union; `kind` names this member.
      std::optional<std::vector<std::string>> items = copy_list(value.list);
      if (!items.has_value()) {
        return std::nullopt;
      }
      return Value{std::move(*items)};
    }
    default:
      return std::nullopt;
  }
}

/// The number of bytes of strings in `observation`, which a plugin's pass budget counts.
///
/// @param observation The observation.
/// @return The bytes of its signal, source and string values.
[[nodiscard]] std::size_t string_bytes(const Observation& observation) {
  std::size_t bytes = observation.signal.size() + observation.source.size();
  if (const auto* text = std::get_if<std::string>(&observation.value)) {
    bytes += text->size();
  }
  if (const auto* items = std::get_if<std::vector<std::string>>(&observation.value)) {
    for (const std::string& item : *items) {
      bytes += item.size();
    }
  }
  return bytes;
}

/// The C value that points into `value`.
///
/// @param value The value to point into. It must outlive the result.
/// @param items Where the items of a list value are written; it must have room for them, so it is not reallocated.
/// @return The C value.
[[nodiscard]] rasp_value c_value(const Value& value, std::vector<rasp_string>& items) {
  if (const bool* flag = std::get_if<bool>(&value)) {
    return {.kind = RASP_VALUE_BOOL, .boolean = *flag};
  }
  if (const std::int64_t* number = std::get_if<std::int64_t>(&value)) {
    return {.kind = RASP_VALUE_INT, .integer = *number};
  }
  if (const std::string* text = std::get_if<std::string>(&value)) {
    return {.kind = RASP_VALUE_STRING, .string = c_string(*text)};
  }
  if (const auto* list = std::get_if<std::vector<std::string>>(&value)) {
    const std::size_t first = items.size();
    for (const std::string& item : *list) {
      items.push_back(c_string(item));
    }
    return {
        .kind = RASP_VALUE_STRING_LIST,
        .list = {.items = list->empty() ? nullptr : std::span(items).subspan(first).data(), .count = list->size()},
    };
  }
  return {.kind = RASP_VALUE_NONE, .integer = 0};
}

}  // namespace

bool valid_name(std::string_view name) {
  if (name.empty() || name.size() > kMaxNameSize || !lower(name.front())) {
    return false;
  }
  return std::ranges::all_of(name, [](char c) { return lower(c) || digit(c) || c == '_'; });
}

std::vector<std::string> parse_list(std::string_view text) {
  std::vector<std::string> names;
  while (!text.empty() && names.size() < kMaxPlugins) {
    const std::size_t end = text.find('\n');
    std::string_view line = text.substr(0, end);
    text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
    if (line.ends_with('\r')) {
      line.remove_suffix(1);
    }
    if (!line.empty()) {
      names.emplace_back(line);
    }
  }
  return names;
}

rasp_host host_info(std::string_view platform, std::string_view config, void* java_vm) {
  return {
      .size = static_cast<std::uint32_t>(sizeof(rasp_host)),
      .api_version = RASP_PLUGIN_API_VERSION,
      .runtime_version = c_string(kRuntimeVersion),
      .platform = c_string(platform),
      .config = c_string(config),
      .java_vm = java_vm,
  };
}

std::optional<Observation> copy_observation(const rasp_observation& observation) {
  std::optional<std::string> signal = copy(observation.signal, kMaxTextSize);
  std::optional<std::string> source = copy(observation.source, kMaxTextSize);
  StatusBits status = 0;
  std::memcpy(&status, &observation.status, sizeof(status));
  if (!signal.has_value() || !source.has_value() || status > static_cast<StatusBits>(RASP_STATUS_TIMEOUT)) {
    return std::nullopt;
  }
  std::optional<Value> value = copy_value(observation.value);
  if (!value.has_value()) {
    return std::nullopt;
  }
  return Observation{
      .signal = std::move(*signal),
      .source = std::move(*source),
      .status = static_cast<Status>(status),
      .value = std::move(*value),
  };
}

ObservationView::ObservationView(std::span<const Observation> observations) {
  std::size_t item_count = 0;
  for (const Observation& observation : observations) {
    if (const auto* list = std::get_if<std::vector<std::string>>(&observation.value)) {
      item_count += list->size();
    }
  }
  items_.reserve(item_count);
  records_.reserve(observations.size());
  for (const Observation& observation : observations) {
    records_.push_back({
        .signal = c_string(observation.signal),
        .source = c_string(observation.source),
        .status = static_cast<rasp_status>(observation.status),
        .value = c_value(observation.value, items_),
    });
  }
}

std::span<const rasp_observation> ObservationView::records() const { return records_; }

Host::Host(std::span<const Listed> listed) {
  load_observations_.reserve(listed.size());
  for (const Listed& entry : listed) {
    std::optional<Plugin> plugin = accept(entry);
    if (plugin.has_value()) {
      load_observations_.push_back(observed(kLoadSignal, entry.name, Value{}));
      plugins_.push_back(std::move(*plugin));
    } else {
      load_observations_.push_back(failed(kLoadSignal, entry.name));
    }
  }
}

std::vector<Observation> Host::run_pass(std::vector<Observation> observations) {
  observations.insert(observations.end(), load_observations_.begin(), load_observations_.end());
  for (Plugin& plugin : plugins_) {
    plugin.sink.observations = &observations;
    plugin.sink.count = 0;
    plugin.sink.bytes = 0;
    for (const CheckFunction run : plugin.checks) {
      run(plugin.state, emit, &plugin.sink);
    }
    plugin.sink.observations = nullptr;
  }
  const ObservationView view(observations);
  for (const Plugin& plugin : plugins_) {
    if (plugin.on_pass != nullptr) {
      plugin.on_pass(plugin.state, view.records().data(), view.records().size());
    }
  }
  return observations;
}

std::optional<Host::Plugin> Host::accept(const Listed& listed) {
  const rasp_plugin* const table = listed.table;
  if (table == nullptr || !valid_name(listed.name) || table->size < kPluginSizeV1 || table->api_version < 1 ||
      table->api_version > RASP_PLUGIN_API_VERSION) {
    return std::nullopt;
  }
  const std::optional<std::string_view> name = view(table->name, kMaxNameSize);
  const std::optional<std::string_view> version = view(table->version, kMaxTextSize);
  if (name != listed.name || !version.has_value() || table->check_count > kMaxChecks ||
      (table->checks == nullptr && table->check_count > 0)) {
    return std::nullopt;
  }
  Plugin plugin{
      .state = table->state,
      .checks = {},
      .on_pass = table->on_pass,
      .sink = {.prefix = listed.name + ".", .name = listed.name, .observations = nullptr, .count = 0, .bytes = 0},
  };
  if (table->check_count == 0) {
    return plugin;
  }
  plugin.checks.reserve(table->check_count);
  for (const rasp_check& check : std::span(table->checks, table->check_count)) {
    if (check.run == nullptr || !view(check.name, kMaxTextSize).has_value()) {
      return std::nullopt;
    }
    plugin.checks.push_back(check.run);
  }
  return plugin;
}

void Host::emit(void* emitter, const rasp_observation* observation) {
  auto* const sink = static_cast<Sink*>(emitter);
  if (sink == nullptr || sink->observations == nullptr || sink->count >= kMaxObservations) {
    return;
  }
  ++sink->count;
  std::optional<Observation> copied = observation == nullptr ? std::nullopt : copy_observation(*observation);
  if (copied.has_value() &&
      (!copied->signal.starts_with(sink->prefix) || copied->signal.size() == sink->prefix.size() ||
       string_bytes(*copied) > kMaxPassBytes - sink->bytes)) {
    copied.reset();
  }
  if (!copied.has_value()) {
    sink->observations->push_back(failed(kRefusedSignal, sink->name));
    return;
  }
  sink->bytes += string_bytes(*copied);
  sink->observations->push_back(std::move(*copied));
}

}  // namespace rasp::plugins
