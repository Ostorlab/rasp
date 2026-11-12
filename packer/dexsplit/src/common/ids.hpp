#include "common/budget.hpp"
#pragma once

#include <cstddef>
#include <string>

namespace dexsplit {

/** Canonical, DEX-portable identity for a method reference.
 *
 *  The triple (declaring class descriptor, name, full prototype descriptor)
 *  uniquely identifies a method across all loaded DEX files.  Owned strings —
 *  safe to store, log, and compare without lifetime concerns.
 *
 *  The `proto` field is the full descriptor (e.g. "(Ljava/lang/String;)V"),
 *  not the shorty.  Shorty collapses every reference type to 'L' and would
 *  collide for overloads such as `f(String)V` vs `f(Object)V`. */
struct MethodId {
  budget::String class_descriptor;  ///< 'L...;' form, e.g. "Ljava/lang/Object;"
  budget::String name;              ///< Method name, e.g. "<init>", "main", "toString"
  budget::String proto;             ///< Full prototype descriptor, e.g. "(I)V"

  bool operator==(const MethodId&) const = default;
};

/** Hash functor for MethodId; suitable for budget::UnorderedMap / budget::UnorderedSet. */
struct MethodIdHash {
  std::size_t operator()(const MethodId& m) const;
};

/** Canonical, DEX-portable identity for a field reference.
 *
 *  The triple (declaring class descriptor, name, type descriptor) uniquely
 *  identifies a field across all loaded DEX files — two fields may share a
 *  name and differ only in type.  Owned strings; safe to store and compare. */
struct FieldId {
  budget::String class_descriptor;  ///< 'L...;' form, e.g. "Ljava/lang/System;"
  budget::String name;              ///< Field name, e.g. "out"
  budget::String type;              ///< Field type descriptor, e.g. "Ljava/io/PrintStream;"

  bool operator==(const FieldId&) const = default;
};

/** Hash functor for FieldId; suitable for budget::UnorderedMap / budget::UnorderedSet. */
struct FieldIdHash {
  std::size_t operator()(const FieldId& f) const;
};

}  // namespace dexsplit
