#include <algorithm>
#include <format>
#include <fstream>
#include <functional>
#include <map>
#include <unordered_map>
#include <unordered_set>

#include "common/budget.hpp"
#include "model/io.hpp"
#include "model/rules.hpp"
#include "raw/byte_writer.hpp"
#include "raw/constants.hpp"
#include "raw/descriptors.hpp"
#include "raw/digest.hpp"
#include "raw/mutf8.hpp"
#include "raw/opcodes.hpp"
#include "raw/parser.hpp"

namespace dexsplit::model {

namespace {

using detail::has;

// write() validates the model before encoding it, so the encoder only fails
// on limits validate() can't see (pool sizes) or on internal errors.  Like
// the reader it reports them with an exception that write() turns into an
// Error.
struct WriteFailure : std::exception {
  Error error;
  explicit WriteFailure(Error value) : error(std::move(value)) {}
  const char* what() const noexcept override { return error.message.c_str(); }
};

[[noreturn]] void fail(Error::Kind kind, budget::String message) {
  throw WriteFailure{Error{kind, std::move(message), {}}};
}

// ===================================================================
// Pools
// ===================================================================

struct StringHash {
  using is_transparent = void;
  std::size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
};

using StringSet = budget::UnorderedSet<budget::String, StringHash, std::equal_to<>>;
template <class V>
using StringMap = budget::UnorderedMap<budget::String, V, StringHash, std::equal_to<>>;

// The pool key of a string: its canonical WTF-8 form (see raw/mutf8.hpp).
// Almost every string is canonical already, so this rarely copies.
class Canon {
 public:
  explicit Canon(std::string_view s) {
    if (raw::mutf8::is_canonical(s)) {
      view_ = s;
    } else {
      storage_ = raw::mutf8::canonical(s);
      view_ = storage_;
    }
  }
  std::string_view view() const { return view_; }

 private:
  budget::String storage_;
  std::string_view view_;
};

bool is_canonical(const FieldId& f) {
  return raw::mutf8::is_canonical(f.class_descriptor) && raw::mutf8::is_canonical(f.name) &&
         raw::mutf8::is_canonical(f.type);
}

bool is_canonical(const MethodId& m) {
  return raw::mutf8::is_canonical(m.class_descriptor) && raw::mutf8::is_canonical(m.name) &&
         raw::mutf8::is_canonical(m.proto);
}

FieldId canonical(const FieldId& f) {
  return {budget::String(Canon(f.class_descriptor).view()), budget::String(Canon(f.name).view()),
          budget::String(Canon(f.type).view())};
}

MethodId canonical(const MethodId& m) {
  return {budget::String(Canon(m.class_descriptor).view()), budget::String(Canon(m.name).view()),
          budget::String(Canon(m.proto).view())};
}

struct MethodHandleHash {
  std::size_t operator()(const MethodHandle& h) const {
    std::size_t member = std::visit(
        [](const auto& m) {
          if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>) {
            return FieldIdHash{}(m);
          } else {
            return MethodIdHash{}(m);
          }
        },
        h.member);
    return member * 31 + static_cast<std::size_t>(h.kind);
  }
};

/** The writer's pools: every string, type, prototype, field, method and
 *  method handle the file refers to.  Collected first, then sorted the way
 *  the format requires and numbered. */
class Pools {
 public:
  // ----- collection -----

  void add_string(std::string_view s) { insert(strings_, Canon(s).view()); }

  void add_type(std::string_view t) {
    Canon c(t);
    if (insert(types_, c.view())) {
      add_string(c.view());
    }
  }

  void add_proto(std::string_view p) {
    Canon c(p);
    if (!insert(protos_, c.view())) {
      return;
    }
    auto parts = raw::parse_proto(c.view());
    if (!parts) {
      return;  // validate() reports it
    }
    add_string(raw::shorty_of(c.view()));
    add_type(parts->return_type);
    for (std::string_view param : parts->params) {
      dexsplit::budget::visit();
      add_type(param);
    }
  }

  void add_field(const FieldId& f) {
    if (is_canonical(f) ? fields_.insert(f).second : fields_.insert(canonical(f)).second) {
      add_type(f.class_descriptor);
      add_string(f.name);
      add_type(f.type);
    }
  }

  void add_method(const MethodId& m) {
    if (is_canonical(m) ? methods_.insert(m).second : methods_.insert(canonical(m)).second) {
      add_type(m.class_descriptor);
      add_string(m.name);
      add_proto(m.proto);
    }
  }

  void add_method_handle(const MethodHandle& h) {
    MethodHandle key = h;
    std::visit([](auto& m) { m = canonical(m); }, key.member);
    if (handles_.insert(key).second) {
      std::visit(
          [&](const auto& m) {
            if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>) {
              add_field(m);
            } else {
              add_method(m);
            }
          },
          h.member);
    }
  }

  void add_value(const Value& v) {
    std::visit(
        [&](const auto& x) {
          using T = std::decay_t<decltype(x)>;
          if constexpr (std::is_same_v<T, Value::String>) {
            add_string(x.value);
          } else if constexpr (std::is_same_v<T, Value::Type>) {
            add_type(x.descriptor);
          } else if constexpr (std::is_same_v<T, Value::Field> || std::is_same_v<T, Value::Enum>) {
            add_field(x.field);
          } else if constexpr (std::is_same_v<T, Value::Method>) {
            add_method(x.method);
          } else if constexpr (std::is_same_v<T, Value::MethodType>) {
            add_proto(x.proto);
          } else if constexpr (std::is_same_v<T, MethodHandle>) {
            add_method_handle(x);
          } else if constexpr (std::is_same_v<T, Value::Array>) {
            for (const Value& e : x.values) {
              dexsplit::budget::visit();
              add_value(e);
            }
          } else if constexpr (std::is_same_v<T, Shared<EncodedAnnotation>>) {
            add_annotation(x.get());
          }
        },
        v.data);
  }

  void add_annotation(const EncodedAnnotation& a) {
    add_type(a.type);
    for (const NamedValue& e : a.elements) {
      dexsplit::budget::visit();
      add_string(e.name);
      add_value(e.value);
    }
  }

  void add_call_site(const CallSite& cs) {
    add_method_handle(cs.bootstrap);
    add_string(cs.method_name);
    add_proto(cs.method_type);
    for (const Value& v : cs.extra_args) {
      dexsplit::budget::visit();
      add_value(v);
    }
  }

  void add_class(const ClassDef& c, bool debug_info) {
    add_type(c.type);
    if (c.superclass) {
      add_type(*c.superclass);
    }
    for (const budget::String& i : c.interfaces) {
      dexsplit::budget::visit();
      add_type(i);
    }
    if (c.source_file) {
      add_string(*c.source_file);
    }
    for (const AnnotationItem& a : c.annotations) {
      dexsplit::budget::visit();
      add_annotation(a.annotation);
    }
    for (const FieldDef& f : c.fields) {
      dexsplit::budget::visit();
      add_field(FieldId{c.type, f.name, f.type});
      if (f.initial_value) {
        add_value(*f.initial_value);
      }
      for (const AnnotationItem& a : f.annotations) {
        dexsplit::budget::visit();
        add_annotation(a.annotation);
      }
    }
    for (const MethodDef& m : c.methods) {
      dexsplit::budget::visit();
      add_method(MethodId{c.type, m.name, m.proto});
      for (const AnnotationItem& a : m.annotations) {
        dexsplit::budget::visit();
        add_annotation(a.annotation);
      }
      for (const auto& set : m.parameter_annotations) {
        dexsplit::budget::visit();
        for (const AnnotationItem& a : set) {
          dexsplit::budget::visit();
          add_annotation(a.annotation);
        }
      }
      if (m.code) {
        add_code(*m.code, debug_info);
      }
    }
  }

  void add_code(const Code& code, bool debug_info) {
    for (const Item& item : code.items) {
      dexsplit::budget::visit();
      if (const Insn* insn = std::get_if<Insn>(&item)) {
        add_insn(*insn);
      } else if (!debug_info) {
        continue;
      } else if (const auto* start = std::get_if<LocalStart>(&item)) {
        if (!first_time(kLocal, &start->local.get())) {
          continue;
        }
        const LocalVariable& v = start->local.get();
        if (v.name) {
          add_string(*v.name);
        }
        if (v.type) {
          add_type(*v.type);
        }
        if (v.signature) {
          add_string(*v.signature);
        }
      } else if (const auto* file = std::get_if<SetSourceFile>(&item)) {
        if (file->name) {
          add_string(*file->name);
        }
      }
    }
    for (const TryRange& t : code.tries) {
      dexsplit::budget::visit();
      for (const Catch& c : t.catches) {
        dexsplit::budget::visit();
        add_type(c.type);
      }
    }
    if (debug_info) {
      for (const auto& name : code.parameter_names) {
        dexsplit::budget::visit();
        if (name) {
          add_string(*name);
        }
      }
    }
  }

  // ----- numbering -----

  void finish() {
    if (strings_.size() > budget::kStrings) {
      throw budget::Exhausted("DEX string compatibility limit exceeded");
    }
    // Strings: by UTF-16 code units.
    string_list_.assign(strings_.begin(), strings_.end());
    budget::sort(string_list_.begin(), string_list_.end(),
                 [](const budget::String& a, const budget::String& b) { return raw::mutf8::compare_utf16(a, b) < 0; });
    for (uint32_t i = 0; i < string_list_.size(); ++i) {
      dexsplit::budget::visit();
      string_index_.emplace(string_list_[i], i);
    }

    // Types: by their descriptor's string index.
    sort_by_key(type_list_, types_, [&](const budget::String& t) { return string_index_.at(t); });
    if (type_list_.size() > 65535) {
      fail(Error::Kind::TooLarge, budget::format("{} types; a DEX file holds at most 65535", type_list_.size()));
    }
    for (uint32_t i = 0; i < type_list_.size(); ++i) {
      dexsplit::budget::visit();
      type_index_.emplace(type_list_[i], i);
    }

    // Prototypes: by return type, then parameter types.
    for (const budget::String& p : protos_) {
      dexsplit::budget::visit();
      ProtoEntry e;
      e.descriptor = p;
      auto parts = raw::parse_proto(p);
      if (!parts) {
        fail(Error::Kind::Invalid, "invalid prototype in writer pool");
      }
      e.shorty = string_index_.at(raw::shorty_of(p));
      e.return_type = find(type_index_, parts->return_type, "type");
      for (std::string_view param : parts->params) {
        dexsplit::budget::visit();
        e.params.push_back(static_cast<uint16_t>(find(type_index_, param, "type")));
      }
      proto_list_.push_back(std::move(e));
    }
    budget::sort(proto_list_.begin(), proto_list_.end(), [](const ProtoEntry& a, const ProtoEntry& b) {
      return std::tie(a.return_type, a.params) < std::tie(b.return_type, b.params);
    });
    if (proto_list_.size() > 65535) {
      fail(Error::Kind::TooLarge, budget::format("{} prototypes; a DEX file holds at most 65535", proto_list_.size()));
    }
    for (uint32_t i = 0; i < proto_list_.size(); ++i) {
      dexsplit::budget::visit();
      proto_index_.emplace(proto_list_[i].descriptor, i);
    }

    // Fields: by class, name, type.
    sort_by_key(field_list_, fields_, [&](const FieldId& f) {
      return std::make_tuple(type_index_.at(f.class_descriptor), string_index_.at(f.name), type_index_.at(f.type));
    });
    if (field_list_.size() > 65536) {
      fail(Error::Kind::TooLarge,
           budget::format("{} field references; a DEX file holds at most 65536", field_list_.size()));
    }
    for (uint32_t i = 0; i < field_list_.size(); ++i) {
      dexsplit::budget::visit();
      field_index_.emplace(field_list_[i], i);
    }

    // Methods: by class, name, prototype.
    sort_by_key(method_list_, methods_, [&](const MethodId& m) {
      return std::make_tuple(type_index_.at(m.class_descriptor), string_index_.at(m.name), proto_index_.at(m.proto));
    });
    if (method_list_.size() > 65536) {
      fail(Error::Kind::TooLarge,
           budget::format("{} method references; a DEX file holds at most 65536", method_list_.size()));
    }
    for (uint32_t i = 0; i < method_list_.size(); ++i) {
      dexsplit::budget::visit();
      method_index_.emplace(method_list_[i], i);
    }

    // Method handles: the format has no order; sort for determinism.
    sort_by_key(handle_list_, handles_, [&](const MethodHandle& h) {
      uint32_t member = std::visit(
          [&](const auto& m) -> uint32_t {
            if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>) {
              return field_index_.at(m);
            } else {
              return method_index_.at(m);
            }
          },
          h.member);
      return std::make_pair(static_cast<uint32_t>(h.kind), member);
    });
    if (handle_list_.size() > 65536) {
      fail(Error::Kind::TooLarge,
           budget::format("{} method handles; a DEX file holds at most 65536", handle_list_.size()));
    }
    for (uint32_t i = 0; i < handle_list_.size(); ++i) {
      dexsplit::budget::visit();
      handle_index_.emplace(handle_list_[i], i);
    }
  }

  // Fill @p out with the elements of @p set sorted by key(element); each key
  // is computed once.
  template <class T, class Set, class Key>
  static void sort_by_key(budget::Vector<T>& out, const Set& set, Key key) {
    using K = decltype(key(std::declval<const T&>()));
    budget::Vector<std::pair<K, const T*>> keyed;
    keyed.reserve(set.size());
    for (const T& x : set) {
      dexsplit::budget::visit();
      keyed.emplace_back(key(x), &x);
    }
    budget::sort(keyed.begin(), keyed.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    out.clear();
    out.reserve(keyed.size());
    for (const auto& [k, x] : keyed) {
      dexsplit::budget::visit();
      out.push_back(*x);
    }
  }

  // ----- lookups (after finish) -----

  enum Kind : uint8_t { kString, kType, kProto, kField, kMethod, kHandle, kCallSite, kLocal, kKinds };

  uint32_t string(std::string_view s) const { return find(string_index_, Canon(s).view(), "string"); }
  uint32_t type(std::string_view t) const { return find(type_index_, Canon(t).view(), "type"); }
  uint32_t proto(std::string_view p) const { return find(proto_index_, Canon(p).view(), "prototype"); }
  uint32_t field(const FieldId& f) const {
    return is_canonical(f) ? find(field_index_, f, "field") : find(field_index_, canonical(f), "field");
  }
  uint32_t method(const MethodId& m) const {
    return is_canonical(m) ? find(method_index_, m, "method") : find(method_index_, canonical(m), "method");
  }
  uint32_t method_handle(const MethodHandle& h) const {
    MethodHandle key = h;
    std::visit([](auto& m) { m = canonical(m); }, key.member);
    return find(handle_index_, key, "method handle");
  }

  // Instruction operands repeat the same shared values: look each up once
  // per pool.  (The same shared string can be a constant and a type.)
  template <class T, class Lookup>
  uint32_t memo(Kind kind, const Shared<T>& value, Lookup lookup) const {
    const void* key = &value.get();
    auto it = memo_[kind].find(key);
    if (it != memo_[kind].end()) {
      return it->second;
    }
    uint32_t index = lookup(value.get());
    memo_[kind].emplace(key, index);
    return index;
  }

  struct ProtoEntry {
    budget::String descriptor;
    uint32_t shorty = 0;
    uint32_t return_type = 0;
    budget::Vector<uint16_t> params;
  };

  const budget::Vector<budget::String>& strings() const { return string_list_; }
  const budget::Vector<budget::String>& types() const { return type_list_; }
  const budget::Vector<ProtoEntry>& protos() const { return proto_list_; }
  const budget::Vector<FieldId>& fields() const { return field_list_; }
  const budget::Vector<MethodId>& methods() const { return method_list_; }
  const budget::Vector<MethodHandle>& method_handles() const { return handle_list_; }

  std::size_t string_count() const { return strings_.size(); }
  std::size_t type_count() const { return types_.size(); }
  std::size_t proto_count() const { return protos_.size(); }
  std::size_t field_count() const { return fields_.size(); }
  std::size_t method_count() const { return methods_.size(); }
  std::size_t method_handle_count() const { return handles_.size(); }

 private:
  // Insert a string unless present, without building a string when it is.
  static bool insert(StringSet& set, std::string_view s) {
    if (set.contains(s)) {
      return false;
    }
    set.emplace(s);
    return true;
  }

  template <class Map, class Key>
  static uint32_t find(const Map& map, const Key& key, const char* what) {
    auto it = map.find(key);
    if (it == map.end()) {
      fail(Error::Kind::Invalid, budget::format("internal error: a {} was not collected", what));
    }
    return it->second;
  }

  // True the first time a shared value is collected into a pool: shared
  // operands are collected once.
  bool first_time(Kind kind, const void* shared) { return seen_[kind].insert(shared).second; }

  void add_insn(const Insn& insn) {
    std::visit(
        [&](const auto& x) {
          using T = std::decay_t<decltype(x)>;
          if constexpr (std::is_same_v<T, ConstString>) {
            if (first_time(kString, &x.value.get())) {
              add_string(x.value.get());
            }
          } else if constexpr (std::is_same_v<T, ConstClass> || std::is_same_v<T, CheckCast> ||
                               std::is_same_v<T, InstanceOf> || std::is_same_v<T, NewInstance> ||
                               std::is_same_v<T, NewArray> || std::is_same_v<T, FilledNewArray>) {
            if (first_time(kType, &x.type.get())) {
              add_type(x.type.get());
            }
          } else if constexpr (std::is_same_v<T, ConstMethodType>) {
            if (first_time(kProto, &x.proto.get())) {
              add_proto(x.proto.get());
            }
          } else if constexpr (std::is_same_v<T, ConstMethodHandle>) {
            if (first_time(kHandle, &x.handle.get())) {
              add_method_handle(x.handle.get());
            }
          } else if constexpr (std::is_same_v<T, InstanceGet> || std::is_same_v<T, InstancePut> ||
                               std::is_same_v<T, StaticGet> || std::is_same_v<T, StaticPut>) {
            if (first_time(kField, &x.field.get())) {
              add_field(x.field.get());
            }
          } else if constexpr (std::is_same_v<T, Invoke>) {
            if (first_time(kMethod, &x.method.get())) {
              add_method(x.method.get());
            }
          } else if constexpr (std::is_same_v<T, InvokePolymorphic>) {
            if (first_time(kMethod, &x.method.get())) {
              add_method(x.method.get());
            }
            if (first_time(kProto, &x.proto.get())) {
              add_proto(x.proto.get());
            }
          } else if constexpr (std::is_same_v<T, InvokeCustom>) {
            if (first_time(kCallSite, &x.call_site.get())) {
              add_call_site(x.call_site.get());
            }
          }
        },
        insn);
  }

  StringSet strings_, types_, protos_;
  budget::UnorderedSet<FieldId, FieldIdHash> fields_;
  budget::UnorderedSet<MethodId, MethodIdHash> methods_;
  budget::UnorderedSet<MethodHandle, MethodHandleHash> handles_;
  budget::UnorderedSet<const void*> seen_[kKinds];

  budget::Vector<budget::String> string_list_, type_list_;
  budget::Vector<ProtoEntry> proto_list_;
  budget::Vector<FieldId> field_list_;
  budget::Vector<MethodId> method_list_;
  budget::Vector<MethodHandle> handle_list_;
  StringMap<uint32_t> string_index_, type_index_, proto_index_;
  budget::UnorderedMap<FieldId, uint32_t, FieldIdHash> field_index_;
  budget::UnorderedMap<MethodId, uint32_t, MethodIdHash> method_index_;
  budget::UnorderedMap<MethodHandle, uint32_t, MethodHandleHash> handle_index_;
  mutable budget::UnorderedMap<const void*, uint32_t> memo_[kKinds];
};

/** Call sites numbered by first use.  Two call sites are written as one when
 *  they have the same non-zero share_key and the same contents. */
class CallSites {
 public:
  uint32_t id(const CallSite& site) {
    if (site.share_key != 0) {
      auto& candidates = by_key_[site.share_key];
      for (uint32_t i : candidates) {
        dexsplit::budget::visit();
        if (*list_[i] == site) {
          return i;
        }
      }
      candidates.push_back(static_cast<uint32_t>(list_.size()));
    }
    list_.push_back(&site);
    return static_cast<uint32_t>(list_.size() - 1);
  }
  const budget::Vector<const CallSite*>& list() const { return list_; }

 private:
  budget::Vector<const CallSite*> list_;
  budget::UnorderedMap<uint32_t, budget::Vector<uint32_t>> by_key_;
};

// ===================================================================
// Encoded values
// ===================================================================

// Smallest number of bytes holding @p v sign-extended.
uint32_t signed_size(int64_t v) {
  uint32_t n = 1;
  while (n < 8) {
    dexsplit::budget::visit();
    int64_t lo = -static_cast<int64_t>(uint64_t{1} << (8U * n - 1U));
    int64_t hi = static_cast<int64_t>(uint64_t{1} << (8U * n - 1U)) - 1;
    if (v >= lo && v <= hi) {
      break;
    }
    ++n;
  }
  return n;
}

// Smallest number of bytes holding @p v zero-extended.
uint32_t unsigned_size(uint64_t v) {
  uint32_t n = 1;
  while (n < 8 && (v >> (8 * n)) != 0) {
    dexsplit::budget::visit();
    ++n;
  }
  return n;
}

class ValueEncoder {
 public:
  explicit ValueEncoder(const Pools& pools) : pools_(pools) {}

  void value(raw::ByteWriter& out, const Value& v) const {
    std::visit([&](const auto& x) { encode(out, x); }, v.data);
  }

  void array(raw::ByteWriter& out, std::span<const Value> values) const {
    out.uleb128(static_cast<uint32_t>(values.size()));
    for (const Value& v : values) {
      dexsplit::budget::visit();
      value(out, v);
    }
  }

  void annotation(raw::ByteWriter& out, const EncodedAnnotation& a) const {
    out.uleb128(pools_.type(a.type));
    // Elements in increasing order of their name's string index.
    budget::Vector<std::pair<uint32_t, const Value*>> elements;
    for (const NamedValue& e : a.elements) {
      dexsplit::budget::visit();
      elements.emplace_back(pools_.string(e.name), &e.value);
    }
    budget::sort(elements.begin(), elements.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
    out.uleb128(static_cast<uint32_t>(elements.size()));
    for (const auto& [name, v] : elements) {
      dexsplit::budget::visit();
      out.uleb128(name);
      value(out, *v);
    }
  }

 private:
  static void header(raw::ByteWriter& out, uint8_t type, uint32_t arg) {
    out.u8(static_cast<uint8_t>((arg << 5U) | type));
  }
  static void bytes(raw::ByteWriter& out, std::pair<uint64_t, uint32_t> encoded) {
    auto [v, n] = encoded;
    for (uint32_t i = 0; i < n; ++i) {
      dexsplit::budget::visit();
      out.u8(static_cast<uint8_t>(v >> (8 * i)));
    }
  }
  static void signed_value(raw::ByteWriter& out, int64_t v, raw::EncodedValue::Type tag) {
    auto type = static_cast<uint8_t>(tag);
    uint32_t n = signed_size(v);
    header(out, type, n - 1);
    bytes(out, {static_cast<uint64_t>(v), n});
  }
  static void unsigned_value(raw::ByteWriter& out, uint64_t v, raw::EncodedValue::Type tag) {
    auto type = static_cast<uint8_t>(tag);
    uint32_t n = unsigned_size(v);
    header(out, type, n - 1);
    bytes(out, {v, n});
  }
  // Floats are stored right-zero-extended: trailing zero bytes of the low
  // end are dropped.
  static void float_value(raw::ByteWriter& out, std::pair<uint64_t, uint32_t> encoded, raw::EncodedValue::Type tag) {
    auto [bits, width] = encoded;
    auto type = static_cast<uint8_t>(tag);
    uint32_t n = width;
    while (n > 1U && ((bits >> (8U * (width - n))) & 0xFFU) == 0U) {
      dexsplit::budget::visit();
      --n;
    }
    header(out, type, n - 1);
    bytes(out, {bits >> (8 * (width - n)), n});
  }

  void encode(raw::ByteWriter& out, const Value::Null&) const { header(out, 0x1e, 0); }
  void encode(raw::ByteWriter& out, const Value::Boolean& x) const { header(out, 0x1f, x.value ? 1 : 0); }
  void encode(raw::ByteWriter& out, const Value::Byte& x) const {
    header(out, 0x00, 0);
    out.u8(static_cast<uint8_t>(x.value));
  }
  void encode(raw::ByteWriter& out, const Value::Short& x) const {
    signed_value(out, x.value, raw::EncodedValue::Type::Short);
  }
  void encode(raw::ByteWriter& out, const Value::Char& x) const {
    unsigned_value(out, static_cast<uint16_t>(x.value), raw::EncodedValue::Type::Char);
  }
  void encode(raw::ByteWriter& out, const Value::Int& x) const {
    signed_value(out, x.value, raw::EncodedValue::Type::Int);
  }
  void encode(raw::ByteWriter& out, const Value::Long& x) const {
    signed_value(out, x.value, raw::EncodedValue::Type::Long);
  }
  void encode(raw::ByteWriter& out, const Value::Float& x) const {
    float_value(out, {std::bit_cast<uint32_t>(x.value), 4}, raw::EncodedValue::Type::Float);
  }
  void encode(raw::ByteWriter& out, const Value::Double& x) const {
    float_value(out, {std::bit_cast<uint64_t>(x.value), 8}, raw::EncodedValue::Type::Double);
  }
  void encode(raw::ByteWriter& out, const Value::String& x) const {
    unsigned_value(out, pools_.string(x.value), raw::EncodedValue::Type::String);
  }
  void encode(raw::ByteWriter& out, const Value::Type& x) const {
    unsigned_value(out, pools_.type(x.descriptor), raw::EncodedValue::Type::Type);
  }
  void encode(raw::ByteWriter& out, const Value::Field& x) const {
    unsigned_value(out, pools_.field(x.field), raw::EncodedValue::Type::Field);
  }
  void encode(raw::ByteWriter& out, const Value::Method& x) const {
    unsigned_value(out, pools_.method(x.method), raw::EncodedValue::Type::Method);
  }
  void encode(raw::ByteWriter& out, const Value::Enum& x) const {
    unsigned_value(out, pools_.field(x.field), raw::EncodedValue::Type::Enum);
  }
  void encode(raw::ByteWriter& out, const Value::MethodType& x) const {
    unsigned_value(out, pools_.proto(x.proto), raw::EncodedValue::Type::MethodType);
  }
  void encode(raw::ByteWriter& out, const MethodHandle& x) const {
    unsigned_value(out, pools_.method_handle(x), raw::EncodedValue::Type::MethodHandle);
  }
  void encode(raw::ByteWriter& out, const Value::Array& x) const {
    header(out, 0x1c, 0);
    array(out, x.values);
  }
  void encode(raw::ByteWriter& out, const Shared<EncodedAnnotation>& x) const {
    header(out, 0x1d, 0);
    annotation(out, x.get());
  }

  const Pools& pools_;
};

/** A field type's default value, for gaps in a static-values array. */
Value default_value(std::string_view type) {
  switch (type.empty() ? 'L' : type.front()) {
    case 'Z':
      return Value{Value::Boolean{false}};
    case 'B':
      return Value{Value::Byte{0}};
    case 'S':
      return Value{Value::Short{0}};
    case 'C':
      return Value{Value::Char{0}};
    case 'I':
      return Value{Value::Int{0}};
    case 'J':
      return Value{Value::Long{0}};
    case 'F':
      return Value{Value::Float{0}};
    case 'D':
      return Value{Value::Double{0}};
    default:
      return Value{Value::Null{}};
  }
}

// ===================================================================
// Code
// ===================================================================

/** A method's code_item contents, before layout. */
struct CodeOut {
  uint16_t registers = 0;
  uint16_t ins = 0;
  uint16_t outs = 0;
  budget::Vector<uint16_t> insns;
  struct Try {
    uint32_t start;
    uint16_t count;
    uint16_t handler_off;
  };
  budget::Vector<Try> tries;
  budget::Vector<uint8_t> handlers;  ///< encoded_catch_handler_list
  budget::Vector<uint8_t> debug;     ///< debug_info_item; empty for none
};

class CodeEncoder {
 public:
  CodeEncoder(const Pools& pools, CallSites& sites, budget::String where)
      : pools_(pools), sites_(sites), where_(std::move(where)) {}

  CodeOut encode(const MethodDef& method, const Code& code, bool debug_info);

 private:
  // How a branch is encoded; the forms of one branch only ever grow.
  enum class Form : uint8_t {
    Fixed,
    Goto8,   // goto +AA
    Goto16,  // goto/16 +AAAA
    Goto32,  // goto/32 +AAAAAAAA (the only one that may branch to itself)
    IfNear,  // if-* +CCCC
    IfNop,   // nop; if-* (a branch to itself goes back to the nop)
    IfFar,   // if-!cond +5; goto/32 target (out of 16-bit range)
  };

  struct Slot {
    uint32_t item = 0;       // index in Code::items
    raw::InsnFields fields;  // the instruction, for every form but the branches
    Form form = Form::Fixed;
    uint32_t units = 0;
    Label target;          // branches
    bool payload = false;  // switch or fill-array-data: has a payload
  };

  [[noreturn]] void fail_at(uint32_t item, std::string_view message) const {
    fail(Error::Kind::Invalid, budget::format("{}, item {}: {}", where_, item, message));
  }

  raw::InsnFields fields_of(const Insn& insn, uint32_t item);
  static uint32_t form_units(Form form);
  static bool fits(Form form, int64_t offset);

  const Pools& pools_;
  CallSites& sites_;
  budget::String where_;
};

uint32_t CodeEncoder::form_units(Form form) {
  switch (form) {
    case Form::Goto8:
      return 1;
    case Form::Goto16:
    case Form::IfNear:
      return 2;
    case Form::Goto32:
    case Form::IfNop:
      return 3;
    case Form::IfFar:
      return 5;
    case Form::Fixed:
      break;
  }
  return 0;
}

bool CodeEncoder::fits(Form form, int64_t offset) {
  switch (form) {
    case Form::Goto8:
      return offset != 0 && offset >= -128 && offset <= 127;
    case Form::Goto16:
    case Form::IfNear:
    case Form::IfNop:
      return offset != 0 && offset >= -32768 && offset <= 32767;
    case Form::Goto32:
    case Form::IfFar:
      return true;
    case Form::Fixed:
      break;
  }
  return true;
}

raw::InsnFields CodeEncoder::fields_of(const Insn& insn, uint32_t item) {
  raw::InsnFields f;
  auto set_args = [&](const RegList& args, std::pair<uint8_t, uint8_t> opcodes) {
    auto [op_35c, op_3rc] = opcodes;
    if (detail::args_fit_35c(args)) {
      f.opcode = op_35c;
      f.a = static_cast<uint32_t>(args.size());
      for (std::size_t i = 0; i < args.size(); ++i) {
        dexsplit::budget::visit();
        f.args[i] = args[i];
      }
    } else if (detail::args_encodable(args)) {
      f.opcode = op_3rc;
      f.a = static_cast<uint32_t>(args.size());
      f.c = args.empty() ? 0 : args[0];
    } else {
      fail_at(item, "argument registers are neither five below v16 nor a run");
    }
  };
  auto kind = [](ValueKind k) { return static_cast<uint8_t>(k); };

  std::visit(
      [&](const auto& x) {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, Nop>) {
          f.opcode = 0x00;
        } else if constexpr (std::is_same_v<T, Move>) {
          uint8_t base = static_cast<uint8_t>(0x01 + 3 * kind(x.kind));
          f.a = x.dest;
          f.b = x.src;
          f.opcode = (x.dest < 16 && x.src < 16) ? base
                     : x.dest < 256              ? static_cast<uint8_t>(base + 1)
                                                 : static_cast<uint8_t>(base + 2);
        } else if constexpr (std::is_same_v<T, MoveResult>) {
          f.opcode = static_cast<uint8_t>(0x0a + kind(x.kind));
          f.a = x.dest;
        } else if constexpr (std::is_same_v<T, MoveException>) {
          f.opcode = 0x0d;
          f.a = x.dest;
        } else if constexpr (std::is_same_v<T, ReturnVoid>) {
          f.opcode = 0x0e;
        } else if constexpr (std::is_same_v<T, Return>) {
          f.opcode = static_cast<uint8_t>(0x0f + kind(x.kind));
          f.a = x.src;
        } else if constexpr (std::is_same_v<T, Const>) {
          f.a = x.dest;
          if (x.dest < 16 && x.value >= -8 && x.value <= 7) {
            f.opcode = 0x12;
            f.literal = x.value;
          } else if (x.value >= -32768 && x.value <= 32767) {
            f.opcode = 0x13;
            f.literal = x.value;
          } else if ((std::bit_cast<uint32_t>(x.value) & 0xFFFFU) == 0U) {
            f.opcode = 0x15;
            f.literal = static_cast<int16_t>(std::bit_cast<uint32_t>(x.value) >> 16U);
          } else {
            f.opcode = 0x14;
            f.literal = x.value;
          }
        } else if constexpr (std::is_same_v<T, ConstWide>) {
          f.a = x.dest;
          if (x.value >= -32768 && x.value <= 32767) {
            f.opcode = 0x16;
            f.literal = x.value;
          } else if ((std::bit_cast<uint64_t>(x.value) & UINT64_C(0xFFFFFFFFFFFF)) == 0U) {
            f.opcode = 0x19;
            f.literal = static_cast<int16_t>(std::bit_cast<uint64_t>(x.value) >> 48U);
          } else if (x.value >= INT32_MIN && x.value <= INT32_MAX) {
            f.opcode = 0x17;
            f.literal = x.value;
          } else {
            f.opcode = 0x18;
            f.literal = x.value;
          }
        } else if constexpr (std::is_same_v<T, ConstString>) {
          f.a = x.dest;
          f.index = pools_.memo(Pools::kString, x.value, [&](const budget::String& s) { return pools_.string(s); });
          f.opcode = f.index <= 0xFFFF ? 0x1a : 0x1b;
        } else if constexpr (std::is_same_v<T, ConstClass>) {
          f.opcode = 0x1c;
          f.a = x.dest;
          f.index = pools_.memo(Pools::kType, x.type, [&](const budget::String& s) { return pools_.type(s); });
        } else if constexpr (std::is_same_v<T, MonitorEnter>) {
          f.opcode = 0x1d;
          f.a = x.object;
        } else if constexpr (std::is_same_v<T, MonitorExit>) {
          f.opcode = 0x1e;
          f.a = x.object;
        } else if constexpr (std::is_same_v<T, CheckCast>) {
          f.opcode = 0x1f;
          f.a = x.object;
          f.index = pools_.memo(Pools::kType, x.type, [&](const budget::String& s) { return pools_.type(s); });
        } else if constexpr (std::is_same_v<T, InstanceOf>) {
          f.opcode = 0x20;
          f.a = x.dest;
          f.b = x.object;
          f.index = pools_.memo(Pools::kType, x.type, [&](const budget::String& s) { return pools_.type(s); });
        } else if constexpr (std::is_same_v<T, ArrayLength>) {
          f.opcode = 0x21;
          f.a = x.dest;
          f.b = x.array;
        } else if constexpr (std::is_same_v<T, NewInstance>) {
          f.opcode = 0x22;
          f.a = x.dest;
          f.index = pools_.memo(Pools::kType, x.type, [&](const budget::String& s) { return pools_.type(s); });
        } else if constexpr (std::is_same_v<T, NewArray>) {
          f.opcode = 0x23;
          f.a = x.dest;
          f.b = x.size;
          f.index = pools_.memo(Pools::kType, x.type, [&](const budget::String& s) { return pools_.type(s); });
        } else if constexpr (std::is_same_v<T, FilledNewArray>) {
          set_args(x.args, {0x24, 0x25});
          f.index = pools_.memo(Pools::kType, x.type, [&](const budget::String& s) { return pools_.type(s); });
        } else if constexpr (std::is_same_v<T, FillArrayData>) {
          f.opcode = 0x26;
          f.a = x.array;
        } else if constexpr (std::is_same_v<T, Throw>) {
          f.opcode = 0x27;
          f.a = x.exception;
        } else if constexpr (std::is_same_v<T, Switch>) {
          f.a = x.value;  // opcode chosen with the payload
        } else if constexpr (std::is_same_v<T, Compare>) {
          f.opcode = static_cast<uint8_t>(0x2d + static_cast<uint8_t>(x.op));
          f.a = x.dest;
          f.b = x.a;
          f.c = x.b;
        } else if constexpr (std::is_same_v<T, If>) {
          f.opcode = static_cast<uint8_t>(0x32 + static_cast<uint8_t>(x.cond));
          f.a = x.a;
          f.b = x.b;
        } else if constexpr (std::is_same_v<T, IfZero>) {
          f.opcode = static_cast<uint8_t>(0x38 + static_cast<uint8_t>(x.cond));
          f.a = x.value;
        } else if constexpr (std::is_same_v<T, ArrayGet>) {
          f.opcode = static_cast<uint8_t>(0x44 + kind(x.kind));
          f.a = x.dest;
          f.b = x.array;
          f.c = x.index;
        } else if constexpr (std::is_same_v<T, ArrayPut>) {
          f.opcode = static_cast<uint8_t>(0x4b + kind(x.kind));
          f.a = x.value;
          f.b = x.array;
          f.c = x.index;
        } else if constexpr (std::is_same_v<T, InstanceGet> || std::is_same_v<T, InstancePut>) {
          f.opcode = static_cast<uint8_t>((std::is_same_v<T, InstanceGet> ? 0x52 : 0x59) + kind(x.kind));
          if constexpr (std::is_same_v<T, InstanceGet>) {
            f.a = x.dest;
          } else {
            f.a = x.value;
          }
          f.b = x.object;
          f.index = pools_.memo(Pools::kField, x.field, [&](const FieldId& id) { return pools_.field(id); });
        } else if constexpr (std::is_same_v<T, StaticGet> || std::is_same_v<T, StaticPut>) {
          f.opcode = static_cast<uint8_t>((std::is_same_v<T, StaticGet> ? 0x60 : 0x67) + kind(x.kind));
          if constexpr (std::is_same_v<T, StaticGet>) {
            f.a = x.dest;
          } else {
            f.a = x.value;
          }
          f.index = pools_.memo(Pools::kField, x.field, [&](const FieldId& id) { return pools_.field(id); });
        } else if constexpr (std::is_same_v<T, Invoke>) {
          uint8_t k = static_cast<uint8_t>(x.kind);
          set_args(x.args, {static_cast<uint8_t>(0x6e + k), static_cast<uint8_t>(0x74 + k)});
          f.index = pools_.memo(Pools::kMethod, x.method, [&](const MethodId& id) { return pools_.method(id); });
        } else if constexpr (std::is_same_v<T, InvokePolymorphic>) {
          set_args(x.args, {0xfa, 0xfb});
          f.index = pools_.memo(Pools::kMethod, x.method, [&](const MethodId& id) { return pools_.method(id); });
          f.proto = pools_.memo(Pools::kProto, x.proto, [&](const budget::String& s) { return pools_.proto(s); });
        } else if constexpr (std::is_same_v<T, InvokeCustom>) {
          set_args(x.args, {0xfc, 0xfd});
          f.index = sites_.id(x.call_site.get());
        } else if constexpr (std::is_same_v<T, ConstMethodHandle>) {
          f.opcode = 0xfe;
          f.a = x.dest;
          f.index =
              pools_.memo(Pools::kHandle, x.handle, [&](const MethodHandle& h) { return pools_.method_handle(h); });
        } else if constexpr (std::is_same_v<T, ConstMethodType>) {
          f.opcode = 0xff;
          f.a = x.dest;
          f.index = pools_.memo(Pools::kProto, x.proto, [&](const budget::String& s) { return pools_.proto(s); });
        } else if constexpr (std::is_same_v<T, Unary>) {
          f.opcode = static_cast<uint8_t>(0x7b + static_cast<uint8_t>(x.op));
          f.a = x.dest;
          f.b = x.src;
        } else if constexpr (std::is_same_v<T, Binary>) {
          uint8_t op = static_cast<uint8_t>(x.op);
          if (x.dest == x.a && x.a < 16 && x.b < 16) {
            f.opcode = static_cast<uint8_t>(0xb0 + op);
            f.a = x.dest;
            f.b = x.b;
          } else {
            f.opcode = static_cast<uint8_t>(0x90 + op);
            f.a = x.dest;
            f.b = x.a;
            f.c = x.b;
          }
        } else if constexpr (std::is_same_v<T, BinaryLiteral>) {
          uint8_t op = static_cast<uint8_t>(x.op);
          f.a = x.dest;
          f.b = x.src;
          f.literal = x.literal;
          bool lit8 = x.literal >= -128 && x.literal <= 127 && x.dest < 256 && x.src < 256;
          f.opcode = lit8 ? static_cast<uint8_t>(0xd8 + op) : static_cast<uint8_t>(0xd0 + op);
        } else if constexpr (std::is_same_v<T, Goto>) {
          f.opcode = 0x28;
        }
      },
      insn);
  return f;
}

CodeOut CodeEncoder::encode(const MethodDef& method, const Code& code, bool debug_info) {
  const budget::Vector<Item>& items = code.items;
  CodeOut out;
  out.registers = code.registers;
  out.ins = static_cast<uint16_t>(detail::ins_words(method));

  // Where each label is.
  budget::UnorderedMap<uint32_t, uint32_t> label_item;
  for (uint32_t i = 0; i < items.size(); ++i) {
    dexsplit::budget::visit();
    if (const Label* l = std::get_if<Label>(&items[i])) {
      label_item.emplace(l->id, i);
    }
  }

  // One slot per instruction, starting each branch at its smallest form.
  budget::Vector<Slot> slots;
  budget::Vector<uint32_t> slot_of(items.size(), UINT32_MAX);
  uint32_t outs = 0;
  for (uint32_t i = 0; i < items.size(); ++i) {
    dexsplit::budget::visit();
    const Insn* insn = std::get_if<Insn>(&items[i]);
    if (!insn) {
      continue;
    }
    Slot s;
    s.item = i;
    s.fields = fields_of(*insn, i);
    if (const Goto* g = std::get_if<Goto>(insn)) {
      s.form = Form::Goto8;
      s.target = g->target;
    } else if (const If* x = std::get_if<If>(insn)) {
      s.form = Form::IfNear;
      s.target = x->target;
    } else if (const IfZero* x = std::get_if<IfZero>(insn)) {
      s.form = Form::IfNear;
      s.target = x->target;
    } else if (std::holds_alternative<Switch>(*insn) || std::holds_alternative<FillArrayData>(*insn)) {
      s.payload = true;
      s.units = 3;
    }
    s.units = s.form == Form::Fixed ? (s.payload ? 3 : raw::opcode_info(s.fields.opcode).units) : form_units(s.form);
    if (const Invoke* x = std::get_if<Invoke>(insn)) {
      outs = std::max<uint32_t>(outs, static_cast<uint32_t>(x->args.size()));
    } else if (const InvokePolymorphic* x = std::get_if<InvokePolymorphic>(insn)) {
      outs = std::max<uint32_t>(outs, static_cast<uint32_t>(x->args.size()));
    } else if (const InvokeCustom* x = std::get_if<InvokeCustom>(insn)) {
      outs = std::max<uint32_t>(outs, static_cast<uint32_t>(x->args.size()));
    }
    slot_of[i] = static_cast<uint32_t>(slots.size());
    slots.push_back(s);
  }
  out.outs = static_cast<uint16_t>(outs);

  // Addresses of every item (labels and markers take the address of the
  // next instruction); widen branches that don't reach until nothing
  // changes.  Forms only grow, so this ends.
  budget::Vector<uint32_t> addr(items.size() + 1, 0);
  auto layout = [&] {
    uint64_t at = 0;
    for (uint32_t i = 0; i < items.size(); ++i) {
      dexsplit::budget::visit();
      addr[i] = static_cast<uint32_t>(at);
      if (slot_of[i] != UINT32_MAX) {
        at += slots[slot_of[i]].units;
      }
    }
    if (at > UINT32_MAX / 2) {
      fail(Error::Kind::TooLarge, budget::format("{}: the code is too long", where_));
    }
    addr[items.size()] = static_cast<uint32_t>(at);
  };
  auto label_addr = [&](Label l) { return addr[label_item.at(l.id)]; };
  auto branch_offset = [&](const Slot& s) {
    int64_t origin = addr[s.item] + (s.form == Form::IfNop ? 1 : 0) + (s.form == Form::IfFar ? 2 : 0);
    return int64_t{label_addr(s.target)} - origin;
  };
  for (bool changed = true; changed;) {
    dexsplit::budget::visit();
    layout();
    changed = false;
    for (Slot& s : slots) {
      dexsplit::budget::visit();
      if (s.form == Form::Fixed || fits(s.form, branch_offset(s))) {
        continue;
      }
      int64_t offset = branch_offset(s);
      switch (s.form) {
        case Form::Goto8:
          s.form = fits(Form::Goto16, offset) ? Form::Goto16 : Form::Goto32;
          break;
        case Form::Goto16:
          s.form = Form::Goto32;
          break;
        case Form::IfNear:
          s.form = offset == 0 ? Form::IfNop : Form::IfFar;
          break;
        case Form::IfNop:
          s.form = Form::IfFar;
          break;
        default:
          break;
      }
      s.units = form_units(s.form);
      changed = true;
    }
  }

  // Payloads go after the last instruction, each at an even address.
  const uint32_t main_size = addr[items.size()];
  budget::Vector<uint32_t> payload_addr(slots.size(), 0);
  budget::Vector<uint16_t> payloads;
  for (uint32_t k = 0; k < slots.size(); ++k) {
    dexsplit::budget::visit();
    const Slot& s = slots[k];
    if (!s.payload) {
      continue;
    }
    if ((main_size + payloads.size()) % 2 != 0) {
      payloads.push_back(0);  // nop
    }
    payload_addr[k] = main_size + static_cast<uint32_t>(payloads.size());
    const Insn& insn = std::get<Insn>(items[s.item]);
    if (const FillArrayData* fill = std::get_if<FillArrayData>(&insn)) {
      uint32_t count = static_cast<uint32_t>(fill->data.size() / fill->element_width);
      payloads.push_back(raw::FILL_ARRAY_DATA_PAYLOAD);
      payloads.push_back(fill->element_width);
      payloads.push_back(static_cast<uint16_t>(count));
      payloads.push_back(static_cast<uint16_t>(count >> 16U));
      for (std::size_t b = 0; b < fill->data.size(); b += 2) {
        dexsplit::budget::visit();
        uint16_t lo = fill->data[b];
        uint32_t hi = b + 1 < fill->data.size() ? fill->data[b + 1] : 0;
        payloads.push_back(static_cast<uint16_t>(lo | (hi << 8U)));
      }
      slots[k].fields.offset = static_cast<int32_t>(payload_addr[k] - addr[s.item]);
      continue;
    }
    // A switch: packed when the keys are dense enough, else sparse.
    const Switch& sw = std::get<Switch>(insn);
    budget::Vector<Switch::Case> cases = sw.cases;
    budget::sort(cases.begin(), cases.end(),
                 [](const Switch::Case& a, const Switch::Case& b) { return a.key < b.key; });
    const int64_t here = addr[s.item];
    auto rel = [&](Label l) { return static_cast<uint32_t>(int64_t{label_addr(l)} - here); };
    auto put32 = [&](uint32_t v) {
      payloads.push_back(static_cast<uint16_t>(v));
      payloads.push_back(static_cast<uint16_t>(v >> 16U));
    };
    const uint64_t n = cases.size();
    const uint64_t range = n == 0 ? 0 : uint64_t(int64_t{cases.back().key} - cases.front().key) + 1;
    const bool packed = n > 0 && range <= 0xFFFF && 4 + 2 * range <= 2 + 4 * n;
    if (packed) {
      slots[k].fields.opcode = 0x2b;
      payloads.push_back(raw::PACKED_SWITCH_PAYLOAD);
      payloads.push_back(static_cast<uint16_t>(range));
      put32(static_cast<uint32_t>(cases.front().key));
      const uint32_t fallthrough = 3;  // the next instruction, relative to the switch
      std::size_t next = 0;
      for (uint64_t key = 0; key < range; ++key) {
        dexsplit::budget::visit();
        int64_t value = int64_t{cases.front().key} + static_cast<int64_t>(key);
        if (next < cases.size() && cases[next].key == value) {
          put32(rel(cases[next++].target));
        } else {
          put32(fallthrough);
        }
      }
    } else {
      slots[k].fields.opcode = 0x2c;
      payloads.push_back(raw::SPARSE_SWITCH_PAYLOAD);
      payloads.push_back(static_cast<uint16_t>(n));
      for (const Switch::Case& c : cases) {
        dexsplit::budget::visit();
        put32(static_cast<uint32_t>(c.key));
      }
      for (const Switch::Case& c : cases) {
        dexsplit::budget::visit();
        put32(rel(c.target));
      }
    }
    slots[k].fields.offset = static_cast<int32_t>(payload_addr[k] - addr[s.item]);
  }

  // Emit.
  out.insns.reserve(main_size + payloads.size());
  for (const Slot& s : slots) {
    dexsplit::budget::visit();
    raw::InsnFields f = s.fields;
    bool ok = true;
    const int64_t offset = s.form == Form::Fixed ? 0 : branch_offset(s);
    switch (s.form) {
      case Form::Fixed:
        ok = raw::encode_insn(f, out.insns);
        break;
      case Form::Goto8:
      case Form::Goto16:
      case Form::Goto32:
        f.opcode = s.form == Form::Goto8 ? 0x28 : s.form == Form::Goto16 ? 0x29 : 0x2a;
        f.offset = static_cast<int32_t>(offset);
        ok = raw::encode_insn(f, out.insns);
        break;
      case Form::IfNear:
        f.offset = static_cast<int32_t>(offset);
        ok = raw::encode_insn(f, out.insns);
        break;
      case Form::IfNop:
        out.insns.push_back(0);  // nop
        f.offset = static_cast<int32_t>(offset);
        ok = raw::encode_insn(f, out.insns);
        break;
      case Form::IfFar: {
        // Branch over a goto/32 on the opposite condition.
        const Insn& insn = std::get<Insn>(items[s.item]);
        uint8_t base = std::holds_alternative<If>(insn) ? 0x32 : 0x38;
        Condition cond = static_cast<Condition>(f.opcode - base);
        f.opcode = static_cast<uint8_t>(base + static_cast<uint8_t>(detail::negate(cond)));
        f.offset = 5;
        raw::InsnFields jump;
        jump.opcode = 0x2a;
        jump.offset = static_cast<int32_t>(offset);
        ok = raw::encode_insn(f, out.insns) && raw::encode_insn(jump, out.insns);
        break;
      }
    }
    if (!ok) {
      fail_at(s.item, "the instruction's operands do not fit its encoding");
    }
  }
  if (out.insns.size() != main_size) {
    fail(Error::Kind::Invalid, budget::format("{}: internal error laying out code", where_));
  }
  out.insns.insert(out.insns.end(), payloads.begin(), payloads.end());

  // Try ranges.  Ranges may overlap; split the code at every range
  // boundary, give each piece the handlers of the ranges covering it in
  // order (the range listed first wins, as the runtime takes the first
  // matching catch), then join neighbours with equal handlers.  A range's
  // own catch list is kept as it is, duplicates included.
  struct Handler {
    budget::Vector<std::pair<uint32_t, uint32_t>> catches;  // type index, address
    std::optional<uint32_t> catch_all;
    bool operator==(const Handler&) const = default;
  };
  struct Piece {
    uint32_t start, end;
    Handler handler;
  };
  budget::Vector<uint32_t> bounds;
  for (const TryRange& t : code.tries) {
    dexsplit::budget::visit();
    uint32_t start = label_addr(t.start);
    uint32_t end = label_addr(t.end);
    if (start < end) {
      bounds.push_back(start);
      bounds.push_back(end);
    }
  }
  budget::sort(bounds.begin(), bounds.end());
  bounds.erase(std::unique(bounds.begin(), bounds.end()), bounds.end());
  budget::Vector<Piece> pieces;
  for (std::size_t b = 0; b + 1 < bounds.size(); ++b) {
    dexsplit::budget::visit();
    Piece piece{bounds[b], bounds[b + 1], {}};
    for (const TryRange& t : code.tries) {
      dexsplit::budget::visit();
      if (piece.handler.catch_all) {
        break;  // nothing after a catch-all is reached
      }
      if (label_addr(t.start) > piece.start || label_addr(t.end) < piece.end) {
        continue;
      }
      for (const Catch& c : t.catches) {
        dexsplit::budget::visit();
        piece.handler.catches.emplace_back(pools_.type(c.type), label_addr(c.handler));
      }
      if (t.catch_all) {
        piece.handler.catch_all = label_addr(*t.catch_all);
      }
    }
    if (piece.handler.catches.empty() && !piece.handler.catch_all) {
      continue;
    }
    if (!pieces.empty() && pieces.back().end == piece.start && pieces.back().handler == piece.handler) {
      pieces.back().end = piece.end;
    } else {
      pieces.push_back(std::move(piece));
    }
  }
  if (!pieces.empty()) {
    budget::Vector<Handler> handlers;
    budget::Vector<uint16_t> handler_offsets;
    raw::ByteWriter list;
    budget::Vector<std::size_t> piece_handler;
    for (const Piece& p : pieces) {
      dexsplit::budget::visit();
      auto it = std::find(handlers.begin(), handlers.end(), p.handler);
      piece_handler.push_back(static_cast<std::size_t>(it - handlers.begin()));
      if (it == handlers.end()) {
        handlers.push_back(p.handler);
      }
    }
    list.uleb128(static_cast<uint32_t>(handlers.size()));
    for (const Handler& h : handlers) {
      dexsplit::budget::visit();
      if (list.size() > 0xFFFF) {
        fail(Error::Kind::TooLarge, budget::format("{}: too many exception handlers", where_));
      }
      handler_offsets.push_back(static_cast<uint16_t>(list.size()));
      int32_t count = static_cast<int32_t>(h.catches.size());
      list.sleb128(h.catch_all ? -count : count);
      for (const auto& [type, address] : h.catches) {
        dexsplit::budget::visit();
        list.uleb128(type);
        list.uleb128(address);
      }
      if (h.catch_all) {
        list.uleb128(*h.catch_all);
      }
    }
    out.handlers = list.take();
    for (std::size_t k = 0; k < pieces.size(); ++k) {
      dexsplit::budget::visit();
      // A try_item covers at most 65535 code units.
      for (uint32_t start = pieces[k].start; start < pieces[k].end;) {
        dexsplit::budget::visit();
        uint32_t count = std::min<uint32_t>(pieces[k].end - start, 0xFFFF);
        out.tries.push_back({start, static_cast<uint16_t>(count), handler_offsets[piece_handler[k]]});
        start += count;
      }
    }
    if (out.tries.size() > 0xFFFF) {
      fail(Error::Kind::TooLarge, budget::format("{}: too many try ranges", where_));
    }
  }

  // Debug info: replay the markers through the state machine.
  if (debug_info) {
    bool any = !code.parameter_names.empty();
    for (const Item& item : items) {
      dexsplit::budget::visit();
      any = any || (!std::holds_alternative<Insn>(item) && !std::holds_alternative<Label>(item));
    }
    if (any) {
      raw::ByteWriter d;
      uint32_t line = 0;
      for (const Item& item : items) {
        dexsplit::budget::visit();
        if (const LineNumber* l = std::get_if<LineNumber>(&item)) {
          line = l->line;
          break;
        }
      }
      d.uleb128(line);
      d.uleb128(static_cast<uint32_t>(code.parameter_names.size()));
      for (const auto& name : code.parameter_names) {
        dexsplit::budget::visit();
        d.uleb128p1(name ? pools_.string(*name) : raw::NO_INDEX);
      }
      uint32_t at = 0;
      auto advance_to = [&](uint32_t address) {
        if (address > at) {
          d.u8(raw::DBG_ADVANCE_PC);
          d.uleb128(address - at);
          at = address;
        }
      };
      for (uint32_t i = 0; i < items.size(); ++i) {
        dexsplit::budget::visit();
        const Item& item = items[i];
        const uint32_t address = addr[i];
        if (const LineNumber* l = std::get_if<LineNumber>(&item)) {
          int32_t line_delta = static_cast<int32_t>(l->line - line);
          if (line_delta < -4 || line_delta > 10) {
            d.u8(raw::DBG_ADVANCE_LINE);
            d.sleb128(line_delta);
            line_delta = 0;
          }
          uint32_t addr_delta = address - at;
          uint32_t special = static_cast<uint32_t>(line_delta + 4) + addr_delta * 15 + raw::DBG_FIRST_SPECIAL;
          if (addr_delta > 17 || special > 0xFF) {
            advance_to(address);
            special = static_cast<uint32_t>(line_delta + 4) + raw::DBG_FIRST_SPECIAL;
          }
          d.u8(static_cast<uint8_t>(special));
          at = address;
          line = l->line;
        } else if (const LocalStart* s = std::get_if<LocalStart>(&item)) {
          advance_to(address);
          const LocalVariable& v = s->local.get();
          d.u8(v.signature ? raw::DBG_START_LOCAL_EXTENDED : raw::DBG_START_LOCAL);
          d.uleb128(s->reg);
          d.uleb128p1(v.name ? pools_.string(*v.name) : raw::NO_INDEX);
          d.uleb128p1(v.type ? pools_.type(*v.type) : raw::NO_INDEX);
          if (v.signature) {
            d.uleb128p1(pools_.string(*v.signature));
          }
        } else if (const LocalEnd* e = std::get_if<LocalEnd>(&item)) {
          advance_to(address);
          d.u8(raw::DBG_END_LOCAL);
          d.uleb128(e->reg);
        } else if (const LocalRestart* r = std::get_if<LocalRestart>(&item)) {
          advance_to(address);
          d.u8(raw::DBG_RESTART_LOCAL);
          d.uleb128(r->reg);
        } else if (std::holds_alternative<PrologueEnd>(item)) {
          advance_to(address);
          d.u8(raw::DBG_SET_PROLOGUE_END);
        } else if (std::holds_alternative<EpilogueBegin>(item)) {
          advance_to(address);
          d.u8(raw::DBG_SET_EPILOGUE_BEGIN);
        } else if (const SetSourceFile* f = std::get_if<SetSourceFile>(&item)) {
          advance_to(address);
          d.u8(raw::DBG_SET_FILE);
          d.uleb128p1(f->name ? pools_.string(*f->name) : raw::NO_INDEX);
        }
      }
      d.u8(raw::DBG_END_SEQUENCE);
      out.debug = d.take();
    }
  }
  return out;
}

// ===================================================================
// The file
// ===================================================================

struct VectorHash {
  template <class T>
  std::size_t operator()(const budget::Vector<T>& v) const {
    std::size_t h = v.size();
    for (const T& x : v) {
      dexsplit::budget::visit();
      h = h * 1000003u ^ std::hash<T>{}(x);
    }
    return h;
  }
};

class Writer {
 public:
  Writer(const Dex& dex, const WriteOptions& options) : dex_(dex), options_(options) {}

  budget::Vector<uint8_t> run();

 private:
  void order_classes();
  uint32_t type_list(const budget::Vector<uint16_t>& types);

  const Dex& dex_;
  const WriteOptions& options_;
  budget::Vector<const ClassDef*> classes_;
  Pools pools_;
  CallSites sites_;
  raw::ByteWriter out_;

  budget::UnorderedMap<budget::Vector<uint16_t>, uint32_t, VectorHash> type_lists_;
  budget::Vector<budget::Vector<uint16_t>> type_list_order_;
};

// Supertypes defined in the file come before their subtypes (ART rejects
// the file otherwise); the rest keeps the model's order.  A post-order walk
// with an explicit stack: a hierarchy can be thousands of classes deep.
void Writer::order_classes() {
  budget::UnorderedMap<std::string_view, const ClassDef*> by_type;
  for (const ClassDef& c : dex_.classes) {
    dexsplit::budget::visit();
    by_type.emplace(c.type, &c);
  }
  auto supers = [&](const ClassDef* c) {
    budget::Vector<const ClassDef*> out;
    auto add = [&](std::string_view type) {
      auto it = by_type.find(type);
      if (it != by_type.end()) {
        out.push_back(it->second);
      }
    };
    if (c->superclass) {
      add(*c->superclass);
    }
    for (const budget::String& i : c->interfaces) {
      dexsplit::budget::visit();
      add(i);
    }
    return out;
  };
  struct Frame {
    const ClassDef* cls;
    budget::Vector<const ClassDef*> next;
    std::size_t i = 0;
  };
  budget::UnorderedSet<const ClassDef*> seen;
  for (const ClassDef& root : dex_.classes) {
    dexsplit::budget::visit();
    if (!seen.insert(&root).second) {
      continue;
    }
    budget::Vector<Frame> stack;
    stack.push_back({&root, supers(&root)});
    while (!stack.empty()) {
      dexsplit::budget::visit();
      Frame& top = stack.back();
      if (top.i == top.next.size()) {
        classes_.push_back(top.cls);
        stack.pop_back();
        continue;
      }
      const ClassDef* next = top.next[top.i++];
      if (seen.insert(next).second) {
        stack.push_back({next, supers(next)});
      }
    }
  }
}

budget::Vector<uint8_t> Writer::run() {
  order_classes();
  for (const ClassDef* c : classes_) {
    dexsplit::budget::visit();
    pools_.add_class(*c, options_.debug_info);
  }
  pools_.finish();
  const ValueEncoder values(pools_);

  // Encode every method's code first: it numbers the call sites.
  struct MethodOut {
    const MethodDef* method;
    uint32_t index;
    CodeOut code;
    bool has_code;
  };
  struct ClassOut {
    const ClassDef* cls;
    budget::Vector<std::pair<const FieldDef*, uint32_t>> static_fields, instance_fields;
    budget::Vector<MethodOut> direct, virtual_;
  };
  budget::Vector<ClassOut> class_out;
  class_out.reserve(classes_.size());
  for (const ClassDef* c : classes_) {
    dexsplit::budget::visit();
    ClassOut co{c, {}, {}, {}, {}};
    for (const FieldDef& f : c->fields) {
      dexsplit::budget::visit();
      uint32_t idx = pools_.field(FieldId{c->type, f.name, f.type});
      (has(f.access, AccessFlags::Static) ? co.static_fields : co.instance_fields).emplace_back(&f, idx);
    }
    for (const MethodDef& m : c->methods) {
      dexsplit::budget::visit();
      uint32_t idx = pools_.method(MethodId{c->type, m.name, m.proto});
      (detail::is_direct(m) ? co.direct : co.virtual_).push_back(MethodOut{&m, idx, {}, m.code.has_value()});
    }
    auto by_index = [](const auto& a, const auto& b) { return a.second < b.second; };
    budget::sort(co.static_fields.begin(), co.static_fields.end(), by_index);
    budget::sort(co.instance_fields.begin(), co.instance_fields.end(), by_index);
    auto by_method = [](const MethodOut& a, const MethodOut& b) { return a.index < b.index; };
    budget::sort(co.direct.begin(), co.direct.end(), by_method);
    budget::sort(co.virtual_.begin(), co.virtual_.end(), by_method);
    for (auto* list : {&co.direct, &co.virtual_}) {
      dexsplit::budget::visit();
      for (MethodOut& mo : *list) {
        dexsplit::budget::visit();
        if (mo.has_code) {
          CodeEncoder encoder(pools_, sites_, budget::format("{}->{}{}", c->type, mo.method->name, mo.method->proto));
          mo.code = encoder.encode(*mo.method, *mo.method->code, options_.debug_info);
        }
      }
    }
    class_out.push_back(std::move(co));
  }

  if (sites_.list().size() > 65536) {
    fail(Error::Kind::TooLarge, budget::format("{} call sites; a DEX file holds at most 65536", sites_.list().size()));
  }

  // ----- id sections: sizes are known, contents are filled at the end -----
  const auto& strings = pools_.strings();
  const auto& types = pools_.types();
  const auto& protos = pools_.protos();
  const auto& fields = pools_.fields();
  const auto& methods = pools_.methods();
  const auto& handles = pools_.method_handles();
  const auto& sites = sites_.list();

  const uint32_t header_size = 0x70;
  uint32_t at = header_size;
  auto section = [&](std::size_t count, uint32_t item_size) {
    uint32_t off = count == 0 ? 0 : at;
    at += static_cast<uint32_t>(count) * item_size;
    return off;
  };
  const uint32_t string_ids_off = section(strings.size(), 4);
  const uint32_t type_ids_off = section(types.size(), 4);
  const uint32_t proto_ids_off = section(protos.size(), 12);
  const uint32_t field_ids_off = section(fields.size(), 8);
  const uint32_t method_ids_off = section(methods.size(), 8);
  const uint32_t class_defs_off = section(class_out.size(), 32);
  const uint32_t call_site_ids_off = section(sites.size(), 4);
  const uint32_t method_handles_off = section(handles.size(), 8);
  const uint32_t data_off = at;
  out_.append(budget::Vector<uint8_t>(data_off, 0));

  struct MapEntry {
    uint16_t type;
    uint32_t count;
    uint32_t offset;
  };
  budget::Vector<MapEntry> map{{raw::TYPE_HEADER_ITEM, 1, 0}};
  auto add_map = [&](uint16_t type, std::size_t count, uint32_t offset) {
    if (count != 0) {
      map.push_back({type, static_cast<uint32_t>(count), offset});
    }
  };
  add_map(raw::TYPE_STRING_ID_ITEM, strings.size(), string_ids_off);
  add_map(raw::TYPE_TYPE_ID_ITEM, types.size(), type_ids_off);
  add_map(raw::TYPE_PROTO_ID_ITEM, protos.size(), proto_ids_off);
  add_map(raw::TYPE_FIELD_ID_ITEM, fields.size(), field_ids_off);
  add_map(raw::TYPE_METHOD_ID_ITEM, methods.size(), method_ids_off);
  add_map(raw::TYPE_CLASS_DEF_ITEM, class_out.size(), class_defs_off);
  add_map(raw::TYPE_CALL_SITE_ID_ITEM, sites.size(), call_site_ids_off);
  add_map(raw::TYPE_METHOD_HANDLE_ITEM, handles.size(), method_handles_off);

  // ----- code items -----
  budget::UnorderedMap<const MethodDef*, uint32_t> code_offsets;
  budget::Vector<std::pair<std::size_t, const CodeOut*>> debug_patches;
  {
    uint32_t first = 0;
    std::size_t count = 0;
    for (const ClassOut& co : class_out) {
      dexsplit::budget::visit();
      for (const auto* list : {&co.direct, &co.virtual_}) {
        dexsplit::budget::visit();
        for (const MethodOut& mo : *list) {
          dexsplit::budget::visit();
          if (!mo.has_code) {
            continue;
          }
          out_.align(4);
          uint32_t off = static_cast<uint32_t>(out_.size());
          if (count++ == 0) {
            first = off;
          }
          code_offsets[mo.method] = off;
          const CodeOut& c = mo.code;
          out_.u16(c.registers);
          out_.u16(c.ins);
          out_.u16(c.outs);
          out_.u16(static_cast<uint16_t>(c.tries.size()));
          debug_patches.emplace_back(out_.size(), &c);
          out_.u32(0);  // debug_info_off, patched below
          out_.u32(static_cast<uint32_t>(c.insns.size()));
          for (uint16_t u : c.insns) {
            dexsplit::budget::visit();
            out_.u16(u);
          }
          if (!c.tries.empty()) {
            if (c.insns.size() % 2 != 0) {
              out_.u16(0);
            }
            for (const CodeOut::Try& t : c.tries) {
              dexsplit::budget::visit();
              out_.u32(t.start);
              out_.u16(t.count);
              out_.u16(t.handler_off);
            }
            out_.append(c.handlers);
          }
        }
      }
    }
    add_map(raw::TYPE_CODE_ITEM, count, first);
  }

  // ----- debug info: methods with identical debug info share one item -----
  {
    budget::UnorderedMap<budget::Vector<uint8_t>, uint32_t, VectorHash> written;
    uint32_t first = 0;
    for (const auto& [patch_at, code] : debug_patches) {
      dexsplit::budget::visit();
      if (code->debug.empty()) {
        continue;
      }
      auto [it, inserted] = written.emplace(code->debug, static_cast<uint32_t>(out_.size()));
      if (inserted) {
        if (written.size() == 1) {
          first = it->second;
        }
        out_.append(code->debug);
      }
      out_.put_u32(patch_at, it->second);
    }
    add_map(raw::TYPE_DEBUG_INFO_ITEM, written.size(), first);
  }

  // ----- type lists: prototype parameters and interfaces -----
  budget::Vector<uint32_t> proto_params_off(protos.size(), 0);
  budget::Vector<uint32_t> interfaces_off(class_out.size(), 0);
  {
    for (std::size_t i = 0; i < protos.size(); ++i) {
      dexsplit::budget::visit();
      if (!protos[i].params.empty()) {
        type_list(protos[i].params);
      }
    }
    budget::Vector<budget::Vector<uint16_t>> interface_lists(class_out.size());
    for (std::size_t i = 0; i < class_out.size(); ++i) {
      dexsplit::budget::visit();
      for (const budget::String& iface : class_out[i].cls->interfaces) {
        dexsplit::budget::visit();
        interface_lists[i].push_back(static_cast<uint16_t>(pools_.type(iface)));
      }
    }
    for (const auto& list : interface_lists) {
      dexsplit::budget::visit();
      if (!list.empty()) {
        type_list(list);
      }
    }
    uint32_t first = 0;
    for (std::size_t k = 0; k < type_list_order_.size(); ++k) {
      dexsplit::budget::visit();
      out_.align(4);
      uint32_t off = static_cast<uint32_t>(out_.size());
      if (k == 0) {
        first = off;
      }
      type_lists_[type_list_order_[k]] = off;
      out_.u32(static_cast<uint32_t>(type_list_order_[k].size()));
      for (uint16_t t : type_list_order_[k]) {
        dexsplit::budget::visit();
        out_.u16(t);
      }
    }
    add_map(raw::TYPE_TYPE_LIST, type_list_order_.size(), first);
    for (std::size_t i = 0; i < protos.size(); ++i) {
      dexsplit::budget::visit();
      if (!protos[i].params.empty()) {
        proto_params_off[i] = type_lists_.at(protos[i].params);
      }
    }
    for (std::size_t i = 0; i < class_out.size(); ++i) {
      dexsplit::budget::visit();
      if (!interface_lists[i].empty()) {
        interfaces_off[i] = type_lists_.at(interface_lists[i]);
      }
    }
  }

  // ----- string data -----
  budget::Vector<uint32_t> string_data_off(strings.size());
  {
    budget::Vector<uint8_t> mutf8;
    for (std::size_t i = 0; i < strings.size(); ++i) {
      dexsplit::budget::visit();
      string_data_off[i] = static_cast<uint32_t>(out_.size());
      out_.uleb128(raw::mutf8::utf16_length(strings[i]));
      mutf8.clear();
      raw::mutf8::append_mutf8(strings[i], mutf8);
      out_.append(mutf8);
      out_.u8(0);
    }
    add_map(raw::TYPE_STRING_DATA_ITEM, strings.size(), strings.empty() ? 0 : string_data_off[0]);
  }

  // ----- annotation items -----
  // Each distinct annotation is written once; annotation sets refer to them.
  struct AnnotationRef {
    uint32_t type;
    uint32_t offset;
  };
  budget::Vector<budget::Vector<uint8_t>> annotation_bytes;
  budget::UnorderedMap<budget::Vector<uint8_t>, uint32_t, VectorHash> annotation_index;
  auto annotation_id = [&](const AnnotationItem& a) {
    raw::ByteWriter w;
    w.u8(static_cast<uint8_t>(a.visibility));
    values.annotation(w, a.annotation);
    auto [it, inserted] = annotation_index.emplace(w.bytes(), static_cast<uint32_t>(annotation_bytes.size()));
    if (inserted) {
      annotation_bytes.push_back(w.take());
    }
    return it->second;
  };
  // Every annotation set of the file, in order: class, fields, methods, parameters.
  struct ClassAnnotations {
    budget::Vector<uint32_t> class_set;
    budget::Vector<std::pair<uint32_t, budget::Vector<uint32_t>>> fields;   // field idx, ids
    budget::Vector<std::pair<uint32_t, budget::Vector<uint32_t>>> methods;  // method idx, ids
    budget::Vector<std::pair<uint32_t, budget::Vector<budget::Vector<uint32_t>>>> parameters;
  };
  budget::Vector<ClassAnnotations> class_annotations(class_out.size());
  budget::Vector<uint32_t> annotation_type;  // per annotation id
  // Annotations are numbered in the file's own order — members by index,
  // each set by type — not the model's, so the layout does not depend on
  // how the model happens to order them.
  for (std::size_t i = 0; i < class_out.size(); ++i) {
    dexsplit::budget::visit();
    const ClassOut& co = class_out[i];
    ClassAnnotations& ca = class_annotations[i];
    auto ids = [&](const budget::Vector<AnnotationItem>& set) {
      budget::Vector<std::pair<uint32_t, const AnnotationItem*>> by_type;
      for (const AnnotationItem& a : set) {
        dexsplit::budget::visit();
        by_type.emplace_back(pools_.type(a.annotation.type), &a);
      }
      budget::sort(by_type.begin(), by_type.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
      budget::Vector<uint32_t> out;
      for (const auto& [type, a] : by_type) {
        dexsplit::budget::visit();
        uint32_t id = annotation_id(*a);
        if (id >= annotation_type.size()) {
          annotation_type.push_back(type);
        }
        out.push_back(id);
      }
      return out;
    };
    ca.class_set = ids(co.cls->annotations);
    budget::Vector<std::pair<const FieldDef*, uint32_t>> fields = co.static_fields;
    fields.insert(fields.end(), co.instance_fields.begin(), co.instance_fields.end());
    budget::sort(fields.begin(), fields.end(), [](const auto& x, const auto& y) { return x.second < y.second; });
    for (const auto& [f, idx] : fields) {
      dexsplit::budget::visit();
      if (!f->annotations.empty()) {
        ca.fields.emplace_back(idx, ids(f->annotations));
      }
    }
    budget::Vector<const MethodOut*> methods;
    for (const auto* list : {&co.direct, &co.virtual_}) {
      dexsplit::budget::visit();
      for (const MethodOut& mo : *list) {
        dexsplit::budget::visit();
        methods.push_back(&mo);
      }
    }
    budget::sort(methods.begin(), methods.end(),
                 [](const MethodOut* x, const MethodOut* y) { return x->index < y->index; });
    for (const MethodOut* mo : methods) {
      dexsplit::budget::visit();
      const MethodDef& m = *mo->method;
      if (!m.annotations.empty()) {
        ca.methods.emplace_back(mo->index, ids(m.annotations));
      }
      if (!m.parameter_annotations.empty()) {
        budget::Vector<budget::Vector<uint32_t>> sets;
        for (const auto& set : m.parameter_annotations) {
          dexsplit::budget::visit();
          sets.push_back(ids(set));
        }
        ca.parameters.emplace_back(mo->index, std::move(sets));
      }
    }
  }
  budget::Vector<uint32_t> annotation_off(annotation_bytes.size());
  for (std::size_t k = 0; k < annotation_bytes.size(); ++k) {
    dexsplit::budget::visit();
    annotation_off[k] = static_cast<uint32_t>(out_.size());
    out_.append(annotation_bytes[k]);
  }
  add_map(raw::TYPE_ANNOTATION_ITEM, annotation_bytes.size(), annotation_bytes.empty() ? 0 : annotation_off[0]);

  // ----- class data -----
  budget::Vector<uint32_t> class_data_off(class_out.size(), 0);
  {
    uint32_t first = 0;
    std::size_t count = 0;
    for (std::size_t i = 0; i < class_out.size(); ++i) {
      dexsplit::budget::visit();
      const ClassOut& co = class_out[i];
      if (co.static_fields.empty() && co.instance_fields.empty() && co.direct.empty() && co.virtual_.empty()) {
        continue;
      }
      uint32_t off = static_cast<uint32_t>(out_.size());
      if (count++ == 0) {
        first = off;
      }
      class_data_off[i] = off;
      out_.uleb128(static_cast<uint32_t>(co.static_fields.size()));
      out_.uleb128(static_cast<uint32_t>(co.instance_fields.size()));
      out_.uleb128(static_cast<uint32_t>(co.direct.size()));
      out_.uleb128(static_cast<uint32_t>(co.virtual_.size()));
      for (const auto* list : {&co.static_fields, &co.instance_fields}) {
        dexsplit::budget::visit();
        uint32_t prev = 0;
        for (const auto& [f, idx] : *list) {
          dexsplit::budget::visit();
          out_.uleb128(idx - prev);
          out_.uleb128(static_cast<uint32_t>(f->access));
          prev = idx;
        }
      }
      for (const auto* list : {&co.direct, &co.virtual_}) {
        dexsplit::budget::visit();
        uint32_t prev = 0;
        for (const MethodOut& mo : *list) {
          dexsplit::budget::visit();
          out_.uleb128(mo.index - prev);
          out_.uleb128(static_cast<uint32_t>(mo.method->access));
          out_.uleb128(mo.has_code ? code_offsets.at(mo.method) : 0);
          prev = mo.index;
        }
      }
    }
    add_map(raw::TYPE_CLASS_DATA_ITEM, count, first);
  }

  // ----- encoded arrays: static values, then call sites -----
  budget::Vector<uint32_t> static_values_off(class_out.size(), 0);
  budget::Vector<uint32_t> call_site_off(sites.size(), 0);
  {
    budget::UnorderedMap<budget::Vector<uint8_t>, uint32_t, VectorHash> arrays;
    uint32_t first = 0;
    std::size_t count = 0;
    auto emit = [&](budget::Vector<uint8_t> bytes, bool share) {
      if (share) {
        auto it = arrays.find(bytes);
        if (it != arrays.end()) {
          return it->second;
        }
      }
      uint32_t off = static_cast<uint32_t>(out_.size());
      if (count++ == 0) {
        first = off;
      }
      out_.append(bytes);
      if (share) {
        arrays.emplace(std::move(bytes), off);
      }
      return off;
    };
    for (std::size_t i = 0; i < class_out.size(); ++i) {
      dexsplit::budget::visit();
      const auto& statics = class_out[i].static_fields;
      std::size_t last = statics.size();
      while (last > 0 && !statics[last - 1].first->initial_value) {
        dexsplit::budget::visit();
        --last;
      }
      if (last == 0) {
        continue;
      }
      budget::Vector<Value> list;
      for (std::size_t k = 0; k < last; ++k) {
        dexsplit::budget::visit();
        const FieldDef& f = *statics[k].first;
        list.push_back(f.initial_value ? *f.initial_value : default_value(f.type));
      }
      raw::ByteWriter w;
      values.array(w, list);
      static_values_off[i] = emit(w.take(), true);
    }
    // Each call site gets its own item: call_site_ids must be in item order.
    for (std::size_t k = 0; k < sites.size(); ++k) {
      dexsplit::budget::visit();
      const CallSite& cs = *sites[k];
      budget::Vector<Value> list;
      list.push_back(Value{cs.bootstrap});
      list.push_back(Value{Value::String{cs.method_name}});
      list.push_back(Value{Value::MethodType{cs.method_type}});
      list.insert(list.end(), cs.extra_args.begin(), cs.extra_args.end());
      raw::ByteWriter w;
      values.array(w, list);
      call_site_off[k] = emit(w.take(), false);
    }
    add_map(raw::TYPE_ENCODED_ARRAY_ITEM, count, first);
  }

  // ----- annotation sets and set ref lists -----
  budget::Vector<budget::Vector<uint32_t>> set_order;
  budget::UnorderedMap<budget::Vector<uint32_t>, uint32_t, VectorHash> set_ids;
  auto set_id = [&](budget::Vector<uint32_t> ids) {
    // Entries in increasing order of the annotation's type index.
    budget::sort(ids.begin(), ids.end(),
                 [&](uint32_t a, uint32_t b) { return annotation_type[a] < annotation_type[b]; });
    auto [it, inserted] = set_ids.emplace(ids, static_cast<uint32_t>(set_order.size()));
    if (inserted) {
      set_order.push_back(std::move(ids));
    }
    return it->second;
  };
  struct DirectoryIds {
    std::optional<uint32_t> class_set;
    budget::Vector<std::pair<uint32_t, uint32_t>> fields, methods;  // member idx, set id
    budget::Vector<std::pair<uint32_t, budget::Vector<std::optional<uint32_t>>>> parameters;
  };
  budget::Vector<DirectoryIds> directory_ids(class_out.size());
  for (std::size_t i = 0; i < class_out.size(); ++i) {
    dexsplit::budget::visit();
    const ClassAnnotations& ca = class_annotations[i];
    DirectoryIds& d = directory_ids[i];
    if (!ca.class_set.empty()) {
      d.class_set = set_id(ca.class_set);
    }
    for (const auto& [idx, ids] : ca.fields) {
      dexsplit::budget::visit();
      d.fields.emplace_back(idx, set_id(ids));
    }
    for (const auto& [idx, ids] : ca.methods) {
      dexsplit::budget::visit();
      d.methods.emplace_back(idx, set_id(ids));
    }
    for (const auto& [idx, sets] : ca.parameters) {
      dexsplit::budget::visit();
      budget::Vector<std::optional<uint32_t>> refs;
      for (const auto& ids : sets) {
        dexsplit::budget::visit();
        refs.push_back(ids.empty() ? std::nullopt : std::optional(set_id(ids)));
      }
      d.parameters.emplace_back(idx, std::move(refs));
    }
  }
  budget::Vector<uint32_t> set_off(set_order.size());
  {
    uint32_t first = 0;
    for (std::size_t k = 0; k < set_order.size(); ++k) {
      dexsplit::budget::visit();
      out_.align(4);
      set_off[k] = static_cast<uint32_t>(out_.size());
      if (k == 0) {
        first = set_off[k];
      }
      out_.u32(static_cast<uint32_t>(set_order[k].size()));
      for (uint32_t id : set_order[k]) {
        dexsplit::budget::visit();
        out_.u32(annotation_off[id]);
      }
    }
    add_map(raw::TYPE_ANNOTATION_SET_ITEM, set_order.size(), first);
  }
  // Ref lists: one per method with parameter annotations.
  budget::Vector<budget::Vector<uint32_t>> ref_list_offsets(class_out.size());
  {
    uint32_t first = 0;
    std::size_t count = 0;
    for (std::size_t i = 0; i < class_out.size(); ++i) {
      dexsplit::budget::visit();
      for (const auto& [idx, refs] : directory_ids[i].parameters) {
        dexsplit::budget::visit();
        out_.align(4);
        uint32_t off = static_cast<uint32_t>(out_.size());
        if (count++ == 0) {
          first = off;
        }
        ref_list_offsets[i].push_back(off);
        out_.u32(static_cast<uint32_t>(refs.size()));
        for (const auto& ref : refs) {
          dexsplit::budget::visit();
          out_.u32(ref ? set_off[*ref] : 0);
        }
      }
    }
    add_map(raw::TYPE_ANNOTATION_SET_REF_LIST, count, first);
  }

  // ----- annotations directories -----
  budget::Vector<uint32_t> annotations_off(class_out.size(), 0);
  {
    budget::UnorderedMap<budget::Vector<uint8_t>, uint32_t, VectorHash> dirs;
    uint32_t first = 0;
    std::size_t count = 0;
    for (std::size_t i = 0; i < class_out.size(); ++i) {
      dexsplit::budget::visit();
      const DirectoryIds& d = directory_ids[i];
      if (!d.class_set && d.fields.empty() && d.methods.empty() && d.parameters.empty()) {
        continue;
      }
      raw::ByteWriter w;
      w.u32(d.class_set ? set_off[*d.class_set] : 0);
      w.u32(static_cast<uint32_t>(d.fields.size()));
      w.u32(static_cast<uint32_t>(d.methods.size()));
      w.u32(static_cast<uint32_t>(d.parameters.size()));
      for (const auto& [idx, set] : d.fields) {
        dexsplit::budget::visit();
        w.u32(idx);
        w.u32(set_off[set]);
      }
      for (const auto& [idx, set] : d.methods) {
        dexsplit::budget::visit();
        w.u32(idx);
        w.u32(set_off[set]);
      }
      for (std::size_t k = 0; k < d.parameters.size(); ++k) {
        dexsplit::budget::visit();
        w.u32(d.parameters[k].first);
        w.u32(ref_list_offsets[i][k]);
      }
      auto it = dirs.find(w.bytes());
      if (it != dirs.end()) {
        annotations_off[i] = it->second;
        continue;
      }
      out_.align(4);
      uint32_t off = static_cast<uint32_t>(out_.size());
      if (count++ == 0) {
        first = off;
      }
      annotations_off[i] = off;
      out_.append(w.bytes());
      dirs.emplace(w.take(), off);
    }
    add_map(raw::TYPE_ANNOTATIONS_DIRECTORY_ITEM, count, first);
  }

  // ----- map list -----
  out_.align(4);
  const uint32_t map_off = static_cast<uint32_t>(out_.size());
  map.push_back({raw::TYPE_MAP_LIST, 1, map_off});
  budget::sort(map.begin(), map.end(), [](const MapEntry& a, const MapEntry& b) { return a.offset < b.offset; });
  out_.u32(static_cast<uint32_t>(map.size()));
  for (const MapEntry& e : map) {
    dexsplit::budget::visit();
    out_.u16(e.type);
    out_.u16(0);
    out_.u32(e.count);
    out_.u32(e.offset);
  }
  const uint32_t file_size = static_cast<uint32_t>(out_.size());

  // ----- id sections -----
  for (std::size_t i = 0; i < strings.size(); ++i) {
    dexsplit::budget::visit();
    out_.put_u32(string_ids_off + 4 * i, string_data_off[i]);
  }
  for (std::size_t i = 0; i < types.size(); ++i) {
    dexsplit::budget::visit();
    out_.put_u32(type_ids_off + 4 * i, pools_.string(types[i]));
  }
  for (std::size_t i = 0; i < protos.size(); ++i) {
    dexsplit::budget::visit();
    std::size_t at_proto = proto_ids_off + 12 * i;
    out_.put_u32(at_proto, protos[i].shorty);
    out_.put_u32(at_proto + 4, protos[i].return_type);
    out_.put_u32(at_proto + 8, proto_params_off[i]);
  }
  auto put_u16_pair = [&](std::size_t at_item, uint32_t lo, uint32_t hi) {
    out_.put_u32(at_item, (lo & 0xFFFFU) | (hi << 16U));
  };
  for (std::size_t i = 0; i < fields.size(); ++i) {
    dexsplit::budget::visit();
    std::size_t at_field = field_ids_off + 8 * i;
    put_u16_pair(at_field, pools_.type(fields[i].class_descriptor), pools_.type(fields[i].type));
    out_.put_u32(at_field + 4, pools_.string(fields[i].name));
  }
  for (std::size_t i = 0; i < methods.size(); ++i) {
    dexsplit::budget::visit();
    std::size_t at_method = method_ids_off + 8 * i;
    put_u16_pair(at_method, pools_.type(methods[i].class_descriptor), pools_.proto(methods[i].proto));
    out_.put_u32(at_method + 4, pools_.string(methods[i].name));
  }
  for (std::size_t i = 0; i < class_out.size(); ++i) {
    dexsplit::budget::visit();
    const ClassDef& c = *class_out[i].cls;
    std::size_t at_class = class_defs_off + 32 * i;
    out_.put_u32(at_class, pools_.type(c.type));
    out_.put_u32(at_class + 4, static_cast<uint32_t>(c.access));
    out_.put_u32(at_class + 8, c.superclass ? pools_.type(*c.superclass) : raw::NO_INDEX);
    out_.put_u32(at_class + 12, interfaces_off[i]);
    out_.put_u32(at_class + 16, c.source_file ? pools_.string(*c.source_file) : raw::NO_INDEX);
    out_.put_u32(at_class + 20, annotations_off[i]);
    out_.put_u32(at_class + 24, class_data_off[i]);
    out_.put_u32(at_class + 28, static_values_off[i]);
  }
  for (std::size_t i = 0; i < sites.size(); ++i) {
    dexsplit::budget::visit();
    out_.put_u32(call_site_ids_off + 4 * i, call_site_off[i]);
  }
  for (std::size_t i = 0; i < handles.size(); ++i) {
    dexsplit::budget::visit();
    const MethodHandle& h = handles[i];
    uint32_t member = std::visit(
        [&](const auto& m) -> uint32_t {
          if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>) {
            return pools_.field(m);
          } else {
            return pools_.method(m);
          }
        },
        h.member);
    std::size_t at_handle = method_handles_off + 8 * i;
    put_u16_pair(at_handle, static_cast<uint32_t>(h.kind), 0);
    put_u16_pair(at_handle + 4, member, 0);
  }

  // ----- header -----
  budget::Vector<uint8_t> bytes = out_.take();
  raw::ByteWriter header;
  const char magic[8] = {'d',
                         'e',
                         'x',
                         '\n',
                         static_cast<char>('0' + dex_.version / 100 % 10),
                         static_cast<char>('0' + dex_.version / 10 % 10),
                         static_cast<char>('0' + dex_.version % 10),
                         0};
  for (char ch : magic) {
    dexsplit::budget::visit();
    header.u8(static_cast<uint8_t>(ch));
  }
  header.u32(0);                                  // checksum
  header.append(budget::Vector<uint8_t>(20, 0));  // signature
  header.u32(file_size);
  header.u32(header_size);
  header.u32(raw::ENDIAN_CONSTANT);
  header.u32(0);  // link_size
  header.u32(0);  // link_off
  header.u32(map_off);
  header.u32(static_cast<uint32_t>(strings.size()));
  header.u32(string_ids_off);
  header.u32(static_cast<uint32_t>(types.size()));
  header.u32(type_ids_off);
  header.u32(static_cast<uint32_t>(protos.size()));
  header.u32(proto_ids_off);
  header.u32(static_cast<uint32_t>(fields.size()));
  header.u32(field_ids_off);
  header.u32(static_cast<uint32_t>(methods.size()));
  header.u32(method_ids_off);
  header.u32(static_cast<uint32_t>(class_out.size()));
  header.u32(class_defs_off);
  header.u32(file_size - data_off);
  header.u32(data_off);
  std::copy(header.bytes().begin(), header.bytes().end(), bytes.begin());

  // The signature covers everything after it; the checksum covers the signature.
  auto signature = raw::parser::compute_signature(bytes);
  std::copy(signature->begin(), signature->end(), bytes.begin() + 12);
  uint32_t checksum = *raw::parser::compute_checksum(bytes);
  for (int i = 0; i < 4; ++i) {
    dexsplit::budget::visit();
    bytes[8U + i] = static_cast<uint8_t>(checksum >> (8U * i));
  }
  return bytes;
}

uint32_t Writer::type_list(const budget::Vector<uint16_t>& types) {
  auto [it, inserted] = type_lists_.emplace(types, static_cast<uint32_t>(type_list_order_.size()));
  if (inserted) {
    type_list_order_.push_back(types);
  }
  return it->second;
}

}  // namespace

std::expected<budget::Vector<uint8_t>, Error> write(const Dex& dex, const WriteOptions& options) {
  budget::Scope scope(dex.request);
  // A feature of a later version is reported as such, before the problems
  // it causes under the older rules (e.g. a space in a name).
  detail::Checked checked = detail::check(dex);
  const bool known_version = dex.version >= 35 && dex.version <= 40 && dex.version != 36;
  if (known_version && checked.needed_version > dex.version) {
    return std::unexpected(Error{Error::Kind::VersionTooLow,
                                 budget::format("the model needs DEX {:03} ({}), but its version is {:03}",
                                                checked.needed_version, checked.needed_reason, dex.version),
                                 {}});
  }
  budget::Vector<Problem>& problems = checked.problems;
  if (!problems.empty()) {
    budget::String message = budget::format("the model is not valid: {}{}{}", problems[0].where,
                                            problems[0].where.empty() ? "" : ": ", problems[0].message);
    if (problems.size() > 1) {
      message += budget::format(" (and {} more)", problems.size() - 1);
    }
    return std::unexpected(Error{Error::Kind::Invalid, std::move(message), std::move(problems)});
  }
  try {
    return Writer(dex, options).run();
  } catch (WriteFailure& failure) {
    return std::unexpected(std::move(failure.error));
  }
}

std::expected<void, Error> write_file(const Dex& dex, const budget::String& path, const WriteOptions& options) {
  auto bytes = write(dex, options);
  if (!bytes) {
    return std::unexpected(std::move(bytes.error()));
  }
  std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
  if (!out) {
    return std::unexpected(Error{Error::Kind::Io, budget::format("cannot create {}", path), {}});
  }
  out.write(reinterpret_cast<const char*>(bytes->data()), static_cast<std::streamsize>(bytes->size()));
  if (!out) {
    return std::unexpected(Error{Error::Kind::Io, budget::format("cannot write {}", path), {}});
  }
  return {};
}

PoolStats pool_stats(const Dex& dex) {
  budget::Scope scope(dex.request);
  Pools pools;
  CallSites sites;
  PoolStats stats;
  for (const ClassDef& c : dex.classes) {
    dexsplit::budget::visit();
    pools.add_class(c, true);
    for (const MethodDef& m : c.methods) {
      dexsplit::budget::visit();
      if (m.code) {
        for (const Item& item : m.code->items) {
          dexsplit::budget::visit();
          if (const Insn* insn = std::get_if<Insn>(&item)) {
            if (const InvokeCustom* ic = std::get_if<InvokeCustom>(insn)) {
              sites.id(ic->call_site.get());
            }
          }
        }
      }
    }
  }
  stats.strings = pools.string_count();
  stats.types = pools.type_count();
  stats.protos = pools.proto_count();
  stats.fields = pools.field_count();
  stats.methods = pools.method_count();
  stats.method_handles = pools.method_handle_count();
  stats.call_sites = sites.list().size();
  return stats;
}

}  // namespace dexsplit::model
