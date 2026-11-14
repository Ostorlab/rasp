#pragma once

// The pools of the DEX writer.  Internal: not part of the API.

#include <algorithm>
#include <cstdint>
#include <format>
#include <functional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "model/io.hpp"
#include "model/rules.hpp"
#include "raw/descriptors.hpp"
#include "raw/mutf8.hpp"

namespace dexsplit::model::detail {

// write() validates the model before encoding it, so the encoder only fails
// on limits validate() can't see (pool sizes) or on internal errors.  Like
// the reader it reports them with an exception that write() turns into an
// Error.
struct WriteFailure
{
    Error error;
};

[[noreturn]] inline void fail(Error::Kind kind, std::string message)
{
    throw WriteFailure{Error{kind, std::move(message), {}}};
}

struct StringHash
{
    using is_transparent = void;
    std::size_t operator()(std::string_view s) const noexcept
    {
        return std::hash<std::string_view>{}(s);
    }
};

using StringSet = std::unordered_set<std::string, StringHash, std::equal_to<>>;
template <class V>
using StringMap = std::unordered_map<std::string, V, StringHash, std::equal_to<>>;

// The pool key of a string: its canonical WTF-8 form (see raw/mutf8.hpp).
// Almost every string is canonical already, so this rarely copies.
class Canon
{
  public:
    explicit Canon(std::string_view s)
    {
        if (raw::mutf8::is_canonical(s)) {
            view_ = s;
        }
        else {
            storage_ = raw::mutf8::canonical(s);
            view_ = storage_;
        }
    }
    std::string_view view() const { return view_; }

  private:
    std::string storage_;
    std::string_view view_;
};

inline bool is_canonical(const FieldId &f)
{
    return raw::mutf8::is_canonical(f.class_descriptor) && raw::mutf8::is_canonical(f.name) &&
           raw::mutf8::is_canonical(f.type);
}

inline bool is_canonical(const MethodId &m)
{
    return raw::mutf8::is_canonical(m.class_descriptor) && raw::mutf8::is_canonical(m.name) &&
           raw::mutf8::is_canonical(m.proto);
}

inline FieldId canonical(const FieldId &f)
{
    return {std::string(Canon(f.class_descriptor).view()), std::string(Canon(f.name).view()),
            std::string(Canon(f.type).view())};
}

inline MethodId canonical(const MethodId &m)
{
    return {std::string(Canon(m.class_descriptor).view()), std::string(Canon(m.name).view()),
            std::string(Canon(m.proto).view())};
}

struct MethodHandleHash
{
    std::size_t operator()(const MethodHandle &h) const noexcept
    {
        std::size_t member = std::visit(
            [](const auto &m) {
                if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>)
                    return FieldIdHash{}(m);
                else
                    return MethodIdHash{}(m);
            },
            h.member);
        return member * 31 + static_cast<std::size_t>(h.kind);
    }
};

/** The writer's pools: every string, type, prototype, field, method and
 *  method handle the file refers to.  Collected first, then sorted the way
 *  the format requires and numbered. */
class Pools
{
  public:
    // ----- collection -----

    void add_string(std::string_view s) { insert(strings_, Canon(s).view()); }

    void add_type(std::string_view t)
    {
        Canon c(t);
        if (insert(types_, c.view()))
            add_string(c.view());
    }

    void add_proto(std::string_view p)
    {
        Canon c(p);
        if (!insert(protos_, c.view()))
            return;
        auto parts = raw::parse_proto(c.view());
        if (!parts)
            return; // validate() reports it
        add_string(raw::shorty_of(c.view()));
        add_type(parts->return_type);
        for (std::string_view param : parts->params)
            add_type(param);
    }

    void add_field(const FieldId &f)
    {
        if (is_canonical(f) ? fields_.insert(f).second : fields_.insert(canonical(f)).second) {
            add_type(f.class_descriptor);
            add_string(f.name);
            add_type(f.type);
        }
    }

    void add_method(const MethodId &m)
    {
        if (is_canonical(m) ? methods_.insert(m).second : methods_.insert(canonical(m)).second) {
            add_type(m.class_descriptor);
            add_string(m.name);
            add_proto(m.proto);
        }
    }

    void add_method_handle(const MethodHandle &h)
    {
        MethodHandle key = h;
        std::visit([](auto &m) { m = canonical(m); }, key.member);
        if (handles_.insert(key).second) {
            std::visit(
                [&](const auto &m) {
                    if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>)
                        add_field(m);
                    else
                        add_method(m);
                },
                h.member);
        }
    }

    void add_value(const Value &v)
    {
        std::visit(
            [&](const auto &x) {
                using T = std::decay_t<decltype(x)>;
                if constexpr (std::is_same_v<T, Value::String>)
                    add_string(x.value);
                else if constexpr (std::is_same_v<T, Value::Type>)
                    add_type(x.descriptor);
                else if constexpr (std::is_same_v<T, Value::Field> ||
                                   std::is_same_v<T, Value::Enum>)
                    add_field(x.field);
                else if constexpr (std::is_same_v<T, Value::Method>)
                    add_method(x.method);
                else if constexpr (std::is_same_v<T, Value::MethodType>)
                    add_proto(x.proto);
                else if constexpr (std::is_same_v<T, MethodHandle>)
                    add_method_handle(x);
                else if constexpr (std::is_same_v<T, Value::Array>)
                    for (const Value &e : x.values)
                        add_value(e);
                else if constexpr (std::is_same_v<T, Shared<EncodedAnnotation>>)
                    add_annotation(x.get());
            },
            v.data);
    }

    void add_annotation(const EncodedAnnotation &a)
    {
        add_type(a.type);
        for (const NamedValue &e : a.elements) {
            add_string(e.name);
            add_value(e.value);
        }
    }

    void add_call_site(const CallSite &cs)
    {
        add_method_handle(cs.bootstrap);
        add_string(cs.method_name);
        add_proto(cs.method_type);
        for (const Value &v : cs.extra_args)
            add_value(v);
    }

    void add_class(const ClassDef &c, bool debug_info)
    {
        add_type(c.type);
        if (c.superclass)
            add_type(*c.superclass);
        for (const std::string &i : c.interfaces)
            add_type(i);
        if (c.source_file)
            add_string(*c.source_file);
        for (const AnnotationItem &a : c.annotations)
            add_annotation(a.annotation);
        for (const FieldDef &f : c.fields) {
            add_field(FieldId{c.type, f.name, f.type});
            if (f.initial_value)
                add_value(*f.initial_value);
            for (const AnnotationItem &a : f.annotations)
                add_annotation(a.annotation);
        }
        for (const MethodDef &m : c.methods) {
            add_method(MethodId{c.type, m.name, m.proto});
            for (const AnnotationItem &a : m.annotations)
                add_annotation(a.annotation);
            for (const auto &set : m.parameter_annotations)
                for (const AnnotationItem &a : set)
                    add_annotation(a.annotation);
            if (m.code)
                add_code(*m.code, debug_info);
        }
    }

    void add_code(const Code &code, bool debug_info)
    {
        for (const Item &item : code.items) {
            if (const Insn *insn = std::get_if<Insn>(&item))
                add_insn(*insn);
            else if (!debug_info)
                continue;
            else if (const auto *start = std::get_if<LocalStart>(&item)) {
                if (!first_time(kLocal, &start->local.get()))
                    continue;
                const LocalVariable &v = start->local.get();
                if (v.name)
                    add_string(*v.name);
                if (v.type)
                    add_type(*v.type);
                if (v.signature)
                    add_string(*v.signature);
            }
            else if (const auto *file = std::get_if<SetSourceFile>(&item)) {
                if (file->name)
                    add_string(*file->name);
            }
        }
        for (const TryRange &t : code.tries)
            for (const Catch &c : t.catches)
                add_type(c.type);
        if (debug_info)
            for (const auto &name : code.parameter_names)
                if (name)
                    add_string(*name);
    }

    // ----- numbering -----

    void finish()
    {
        // Strings: by UTF-16 code units.
        string_list_.assign(strings_.begin(), strings_.end());
        std::sort(string_list_.begin(), string_list_.end(),
                  [](const std::string &a, const std::string &b) {
                      return raw::mutf8::compare_utf16(a, b) < 0;
                  });
        for (uint32_t i = 0; i < string_list_.size(); ++i)
            string_index_.emplace(string_list_[i], i);

        // Types: by their descriptor's string index.
        sort_by_key(type_list_, types_, [&](const std::string &t) { return string_index_.at(t); });
        if (type_list_.size() > 65535)
            fail(Error::Kind::TooLarge,
                 std::format("{} types; a DEX file holds at most 65535", type_list_.size()));
        for (uint32_t i = 0; i < type_list_.size(); ++i)
            type_index_.emplace(type_list_[i], i);

        // Prototypes: by return type, then parameter types.
        for (const std::string &p : protos_) {
            ProtoEntry e;
            e.descriptor = p;
            auto parts = raw::parse_proto(p);
            if (!parts)
                fail(Error::Kind::Invalid, std::format("\"{}\" is not a prototype", p));
            e.shorty = string_index_.at(raw::shorty_of(p));
            e.return_type = find(type_index_, parts->return_type, "type");
            for (std::string_view param : parts->params)
                e.params.push_back(static_cast<uint16_t>(find(type_index_, param, "type")));
            proto_list_.push_back(std::move(e));
        }
        std::sort(proto_list_.begin(), proto_list_.end(),
                  [](const ProtoEntry &a, const ProtoEntry &b) {
                      return std::tie(a.return_type, a.params) < std::tie(b.return_type, b.params);
                  });
        if (proto_list_.size() > 65535)
            fail(Error::Kind::TooLarge,
                 std::format("{} prototypes; a DEX file holds at most 65535", proto_list_.size()));
        for (uint32_t i = 0; i < proto_list_.size(); ++i)
            proto_index_.emplace(proto_list_[i].descriptor, i);

        // Fields: by class, name, type.
        sort_by_key(field_list_, fields_, [&](const FieldId &f) {
            return std::make_tuple(type_index_.at(f.class_descriptor), string_index_.at(f.name),
                                   type_index_.at(f.type));
        });
        if (field_list_.size() > 65536)
            fail(Error::Kind::TooLarge,
                 std::format("{} field references; a DEX file holds at most 65536",
                             field_list_.size()));
        for (uint32_t i = 0; i < field_list_.size(); ++i)
            field_index_.emplace(field_list_[i], i);

        // Methods: by class, name, prototype.
        sort_by_key(method_list_, methods_, [&](const MethodId &m) {
            return std::make_tuple(type_index_.at(m.class_descriptor), string_index_.at(m.name),
                                   proto_index_.at(m.proto));
        });
        if (method_list_.size() > 65536)
            fail(Error::Kind::TooLarge,
                 std::format("{} method references; a DEX file holds at most 65536",
                             method_list_.size()));
        for (uint32_t i = 0; i < method_list_.size(); ++i)
            method_index_.emplace(method_list_[i], i);

        // Method handles: the format has no order; sort for determinism.
        sort_by_key(handle_list_, handles_, [&](const MethodHandle &h) {
            uint32_t member = std::visit(
                [&](const auto &m) -> uint32_t {
                    if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>)
                        return field_index_.at(m);
                    else
                        return method_index_.at(m);
                },
                h.member);
            return std::make_pair(static_cast<uint32_t>(h.kind), member);
        });
        if (handle_list_.size() > 65536)
            fail(Error::Kind::TooLarge,
                 std::format("{} method handles; a DEX file holds at most 65536",
                             handle_list_.size()));
        for (uint32_t i = 0; i < handle_list_.size(); ++i)
            handle_index_.emplace(handle_list_[i], i);
    }

    // Fill @p out with the elements of @p set sorted by key(element); each key
    // is computed once.
    template <class T, class Set, class Key>
    static void sort_by_key(std::vector<T> &out, const Set &set, Key key)
    {
        using K = decltype(key(std::declval<const T &>()));
        std::vector<std::pair<K, const T *>> keyed;
        keyed.reserve(set.size());
        for (const T &x : set)
            keyed.emplace_back(key(x), &x);
        std::sort(keyed.begin(), keyed.end(),
                  [](const auto &a, const auto &b) { return a.first < b.first; });
        out.clear();
        out.reserve(keyed.size());
        for (const auto &[k, x] : keyed)
            out.push_back(*x);
    }

    // ----- lookups (after finish) -----

    enum Kind : uint8_t {
        kString,
        kType,
        kProto,
        kField,
        kMethod,
        kHandle,
        kCallSite,
        kLocal,
        kKinds
    };

    uint32_t string(std::string_view s) const
    {
        return find(string_index_, Canon(s).view(), "string");
    }
    uint32_t type(std::string_view t) const { return find(type_index_, Canon(t).view(), "type"); }
    uint32_t proto(std::string_view p) const
    {
        return find(proto_index_, Canon(p).view(), "prototype");
    }
    uint32_t field(const FieldId &f) const
    {
        return is_canonical(f) ? find(field_index_, f, "field")
                               : find(field_index_, canonical(f), "field");
    }
    uint32_t method(const MethodId &m) const
    {
        return is_canonical(m) ? find(method_index_, m, "method")
                               : find(method_index_, canonical(m), "method");
    }
    uint32_t method_handle(const MethodHandle &h) const
    {
        MethodHandle key = h;
        std::visit([](auto &m) { m = canonical(m); }, key.member);
        return find(handle_index_, key, "method handle");
    }

    // Instruction operands repeat the same shared values: look each up once
    // per pool.  (The same shared string can be a constant and a type.)
    template <class T, class Lookup>
    uint32_t memo(Kind kind, const Shared<T> &value, Lookup lookup) const
    {
        const void *key = &value.get();
        auto it = memo_[kind].find(key);
        if (it != memo_[kind].end())
            return it->second;
        uint32_t index = lookup(value.get());
        memo_[kind].emplace(key, index);
        return index;
    }

    struct ProtoEntry
    {
        std::string descriptor;
        uint32_t shorty = 0;
        uint32_t return_type = 0;
        std::vector<uint16_t> params;
    };

    const std::vector<std::string> &strings() const { return string_list_; }
    const std::vector<std::string> &types() const { return type_list_; }
    const std::vector<ProtoEntry> &protos() const { return proto_list_; }
    const std::vector<FieldId> &fields() const { return field_list_; }
    const std::vector<MethodId> &methods() const { return method_list_; }
    const std::vector<MethodHandle> &method_handles() const { return handle_list_; }

    std::size_t string_count() const { return strings_.size(); }
    std::size_t type_count() const { return types_.size(); }
    std::size_t proto_count() const { return protos_.size(); }
    std::size_t field_count() const { return fields_.size(); }
    std::size_t method_count() const { return methods_.size(); }
    std::size_t method_handle_count() const { return handles_.size(); }

  private:
    // Insert a string unless present, without building a string when it is.
    static bool insert(StringSet &set, std::string_view s)
    {
        if (set.contains(s))
            return false;
        set.emplace(s);
        return true;
    }

    template <class Map, class Key>
    static uint32_t find(const Map &map, const Key &key, const char *what)
    {
        auto it = map.find(key);
        if (it == map.end())
            fail(Error::Kind::Invalid, std::format("internal error: a {} was not collected", what));
        return it->second;
    }

    // True the first time a shared value is collected into a pool: shared
    // operands are collected once.
    bool first_time(Kind kind, const void *shared) { return seen_[kind].insert(shared).second; }

    void add_insn(const Insn &insn)
    {
        std::visit(
            [&](const auto &x) {
                using T = std::decay_t<decltype(x)>;
                if constexpr (std::is_same_v<T, ConstString>) {
                    if (first_time(kString, &x.value.get()))
                        add_string(x.value.get());
                }
                else if constexpr (std::is_same_v<T, ConstClass> || std::is_same_v<T, CheckCast> ||
                                   std::is_same_v<T, InstanceOf> ||
                                   std::is_same_v<T, NewInstance> || std::is_same_v<T, NewArray> ||
                                   std::is_same_v<T, FilledNewArray>) {
                    if (first_time(kType, &x.type.get()))
                        add_type(x.type.get());
                }
                else if constexpr (std::is_same_v<T, ConstMethodType>) {
                    if (first_time(kProto, &x.proto.get()))
                        add_proto(x.proto.get());
                }
                else if constexpr (std::is_same_v<T, ConstMethodHandle>) {
                    if (first_time(kHandle, &x.handle.get()))
                        add_method_handle(x.handle.get());
                }
                else if constexpr (std::is_same_v<T, InstanceGet> ||
                                   std::is_same_v<T, InstancePut> || std::is_same_v<T, StaticGet> ||
                                   std::is_same_v<T, StaticPut>) {
                    if (first_time(kField, &x.field.get()))
                        add_field(x.field.get());
                }
                else if constexpr (std::is_same_v<T, Invoke>) {
                    if (first_time(kMethod, &x.method.get()))
                        add_method(x.method.get());
                }
                else if constexpr (std::is_same_v<T, InvokePolymorphic>) {
                    if (first_time(kMethod, &x.method.get()))
                        add_method(x.method.get());
                    if (first_time(kProto, &x.proto.get()))
                        add_proto(x.proto.get());
                }
                else if constexpr (std::is_same_v<T, InvokeCustom>) {
                    if (first_time(kCallSite, &x.call_site.get()))
                        add_call_site(x.call_site.get());
                }
            },
            insn);
    }

    StringSet strings_, types_, protos_;
    std::unordered_set<FieldId, FieldIdHash> fields_;
    std::unordered_set<MethodId, MethodIdHash> methods_;
    std::unordered_set<MethodHandle, MethodHandleHash> handles_;
    std::unordered_set<const void *> seen_[kKinds];

    std::vector<std::string> string_list_, type_list_;
    std::vector<ProtoEntry> proto_list_;
    std::vector<FieldId> field_list_;
    std::vector<MethodId> method_list_;
    std::vector<MethodHandle> handle_list_;
    StringMap<uint32_t> string_index_, type_index_, proto_index_;
    std::unordered_map<FieldId, uint32_t, FieldIdHash> field_index_;
    std::unordered_map<MethodId, uint32_t, MethodIdHash> method_index_;
    std::unordered_map<MethodHandle, uint32_t, MethodHandleHash> handle_index_;
    mutable std::unordered_map<const void *, uint32_t> memo_[kKinds];
};

/** Call sites numbered by first use.  Two call sites are written as one when
 *  they have the same non-zero share_key and the same contents. */
class CallSites
{
  public:
    uint32_t id(const CallSite &site)
    {
        if (site.share_key != 0) {
            auto &candidates = by_key_[site.share_key];
            for (uint32_t i : candidates)
                if (*list_[i] == site)
                    return i;
            candidates.push_back(static_cast<uint32_t>(list_.size()));
        }
        list_.push_back(&site);
        return static_cast<uint32_t>(list_.size() - 1);
    }
    const std::vector<const CallSite *> &list() const { return list_; }

  private:
    std::vector<const CallSite *> list_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> by_key_;
};

} // namespace dexsplit::model::detail
