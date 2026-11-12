#include "model/copy.hpp"

#include <type_traits>

namespace dexsplit::model {
namespace {
void text(std::string_view value) { budget::visit(value.size() / 64 + 1); }
void field(const FieldId& value) {
  text(value.class_descriptor);
  text(value.name);
  text(value.type);
}
void method(const MethodId& value) {
  text(value.class_descriptor);
  text(value.name);
  text(value.proto);
}
void value_copy(const Value& value) {
  budget::visit();
  std::visit(
      [](const auto& item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, Value::String>) {
          text(item.value);
        } else if constexpr (std::is_same_v<T, Value::Type>) {
          text(item.descriptor);
        } else if constexpr (std::is_same_v<T, Value::MethodType>) {
          text(item.proto);
        } else if constexpr (std::is_same_v<T, Value::Array>) {
          for (const auto& child : item.values) {
            value_copy(child);
          }
        } else if constexpr (std::is_same_v<T, Value::Field> || std::is_same_v<T, Value::Enum>) {
          field(item.field);
        } else if constexpr (std::is_same_v<T, Value::Method>) {
          method(item.method);
        } else if constexpr (std::is_same_v<T, MethodHandle>) {
          std::visit(
              [](const auto& member) {
                using M = std::decay_t<decltype(member)>;
                if constexpr (std::is_same_v<M, FieldId>) {
                  field(member);
                } else {
                  method(member);
                }
              },
              item.member);
        }
      },
      value.data);
}
void annotations(const budget::Vector<AnnotationItem>& values) {
  for (const auto& annotation : values) {
    budget::visit();
    text(annotation.annotation.type);
    for (const auto& element : annotation.annotation.elements) {
      text(element.name);
      value_copy(element.value);
    }
  }
}
void charge_class(const ClassDef& value) {
  budget::visit();
  text(value.type);
  if (value.superclass) {
    text(*value.superclass);
  }
  if (value.source_file) {
    text(*value.source_file);
  }
  for (const auto& interface : value.interfaces) {
    text(interface);
  }
  annotations(value.annotations);
  for (const auto& member : value.fields) {
    budget::visit();
    text(member.name);
    text(member.type);
    annotations(member.annotations);
    if (member.initial_value) {
      value_copy(*member.initial_value);
    }
  }
  for (const auto& member : value.methods) {
    budget::visit();
    text(member.name);
    text(member.proto);
    annotations(member.annotations);
    for (const auto& list : member.parameter_annotations) {
      annotations(list);
    }
    // CodeValue copies share their immutable instruction vectors and detach before edits.
  }
}
}  // namespace
std::shared_ptr<budget::State> copy_request(Dex& destination, const Dex& source) {
  if (source.request == nullptr) {
    throw budget::Exhausted("source model has no request budget");
  }
  if (destination.request == nullptr ||
      (destination.classes.empty() && destination.request->work == 0 && destination.request->storage == 0)) {
    destination.request = source.request;
  }
  if (destination.request != source.request) {
    throw budget::Exhausted("read all copied models within one Request");
  }
  return destination.request;
}
std::expected<void, Error> copy_classes(Dex& destination, const Dex& source,
                                        std::span<const std::string_view> descriptors) {
  budget::Scope scope(copy_request(destination, source));
  budget::visit();
  if (descriptors.size() > budget::kClasses - std::min(destination.classes.size(), budget::kClasses)) {
    return std::unexpected(Error{Error::Kind::Invalid, "DEX class compatibility limit exceeded", {}});
  }
  if (descriptors.empty()) {
    return {};
  }
  budget::UnorderedMap<std::string_view, const ClassDef*> by_name;
  for (const auto& cls : source.classes) {
    budget::visit();
    by_name.emplace(cls.type, &cls);
  }
  budget::UnorderedSet<std::string_view> seen;
  for (const auto& cls : destination.classes) {
    budget::visit();
    seen.insert(cls.type);
  }
  destination.original.reset();
  for (auto descriptor : descriptors) {
    budget::visit();
    auto found = by_name.find(descriptor);
    if (found == by_name.end()) {
      return std::unexpected(Error{Error::Kind::Invalid, "source has no class", {}});
    }
    if (!seen.insert(descriptor).second) {
      return std::unexpected(Error{Error::Kind::Invalid, "destination already has class", {}});
    }
    charge_class(*found->second);
    destination.classes.push_back(*found->second);
  }
  return {};
}
}  // namespace dexsplit::model
