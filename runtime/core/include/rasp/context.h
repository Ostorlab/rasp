/// Context, the values the plugins share, and Key, the name and the type of one of them.

#pragma once

#include <any>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace rasp::plugins {

/// The name and the type of a value in the context.
///
/// @tparam T The type of the value. It must be copyable.
template <typename T>
struct Key {
  /// The name of the value. No other value in the context has it.
  std::string_view name;
};

/// The values the plugins share, each under its own name. Its methods are safe to call from any thread.
class Context {
 public:
  /// Puts a value, in place of the value that has the same name.
  ///
  /// @tparam T The type of the value, which the key gives.
  /// @param key The name and the type of the value.
  /// @param value The value.
  template <typename T>
  void put(Key<T> key, std::type_identity_t<T> value) {
    const std::scoped_lock lock(mutex_);
    values_.insert_or_assign(std::string(key.name), std::any(std::move(value)));
  }

  /// Reads a value. The context keeps it.
  ///
  /// @tparam T The type of the value, which the key gives.
  /// @param key The name and the type of the value.
  /// @return A copy of the value. Nothing when the context holds no value of this name and this type.
  template <typename T>
  [[nodiscard]] std::optional<T> get(Key<T> key) const {
    const std::scoped_lock lock(mutex_);
    const auto found = values_.find(key.name);
    if (found == values_.end()) {
      return std::nullopt;
    }
    const T* const value = std::any_cast<T>(&found->second);
    if (value == nullptr) {
      return std::nullopt;
    }
    return *value;
  }

  /// Takes a value: the context no longer holds it.
  ///
  /// @tparam T The type of the value, which the key gives.
  /// @param key The name and the type of the value.
  /// @return The value. Nothing, and the context is unchanged, when it holds no value of this name and this type.
  template <typename T>
  [[nodiscard]] std::optional<T> take(Key<T> key) {
    const std::scoped_lock lock(mutex_);
    const auto found = values_.find(key.name);
    if (found == values_.end()) {
      return std::nullopt;
    }
    T* const value = std::any_cast<T>(&found->second);
    if (value == nullptr) {
      return std::nullopt;
    }
    std::optional<T> taken(std::move(*value));
    values_.erase(found);
    return taken;
  }

 private:
  /// Guards `values_`.
  mutable std::mutex mutex_;
  /// The values, by name.
  std::map<std::string, std::any, std::less<>> values_;
};

}  // namespace rasp::plugins
