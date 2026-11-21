/// Reading system properties from the platform's property files directly, without libc.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "util/raw_file.h"

namespace rasp::android::util {

/// A property as its property file holds it.
struct AreaProperty {
  std::string value;
  /// The property's serial: its value's length, its flags and its update counter.
  std::uint32_t serial = 0;

  /// Compares two properties field by field.
  [[nodiscard]] friend bool operator==(const AreaProperty& left, const AreaProperty& right) = default;
};

/// The `property_info` index, which maps each property name to the property file that holds it.
class PropertyIndex {
 public:
  /// Reads the index from its bytes.
  explicit PropertyIndex(std::string_view bytes) : bytes_(bytes) {}

  /// The name of the property file that holds the property `name`.
  ///
  /// @return The file's name, or nothing when the index is malformed or names no file for the property.
  [[nodiscard]] std::optional<std::string_view> file_of(std::string_view name) const;

 private:
  std::string_view bytes_;
};

/// A property file, which holds the values of a group of properties.
class PropertyFile {
 public:
  /// Reads the file from its bytes.
  explicit PropertyFile(std::string_view bytes) : bytes_(bytes) {}

  /// Finds the property `name`.
  ///
  /// @return The property, or nothing when the file doesn't hold it or is malformed.
  [[nodiscard]] std::optional<AreaProperty> find(std::string_view name) const;

 private:
  std::string_view bytes_;
};

/// Whether `serial` shows the value was written again after the property was added. The platform adds each read-only
/// property once and never updates it, so only a direct write to the property file does that.
[[nodiscard]] bool was_rewritten(std::uint32_t serial);

/// The property files of the process, mapped as they are needed.
class PropertyAreas {
 public:
  /// Reads the property files in `directory`, `/dev/__properties__` on a device. A file the process may not open is
  /// read where the process already maps it, as the memory map at `maps_path` shows.
  PropertyAreas(std::string directory, std::string maps_path, rasp::util::ProcReader read = rasp::util::read_proc_file);

  /// Whether the index of the property files could be read.
  [[nodiscard]] bool readable();

  /// Reads the property `name`.
  ///
  /// @return The property, or nothing when it is unset or its file can't be read.
  [[nodiscard]] std::optional<AreaProperty> read(std::string_view name);

 private:
  /// The bytes of the property file `file`, mapped on first use; empty when it can't be read.
  [[nodiscard]] std::string_view area(std::string_view file);
  /// The bytes of `path` where the process already maps it, or empty.
  [[nodiscard]] std::string_view mapped_by_process(std::string_view path);

  std::string directory_;
  std::string maps_path_;
  rasp::util::ProcReader read_;
  bool opened_ = false;
  std::string_view info_;
  std::vector<rasp::util::MappedFile> mappings_;
  std::vector<std::pair<std::string, std::string_view>> areas_;
  std::optional<std::string> maps_;
};

}  // namespace rasp::android::util
