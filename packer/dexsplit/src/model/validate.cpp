#include <format>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "model/io.hpp"
#include "model/rules.hpp"
#include "raw/descriptors.hpp"
#include "raw/mutf8.hpp"

namespace dexsplit::model {

namespace {

using detail::has;

// Access flag bits, as ART's verifier names them.
constexpr uint32_t kPublic = 0x0001;
constexpr uint32_t kPrivate = 0x0002;
constexpr uint32_t kProtected = 0x0004;
constexpr uint32_t kStatic = 0x0008;
constexpr uint32_t kFinal = 0x0010;
constexpr uint32_t kSynchronized = 0x0020;
constexpr uint32_t kVolatile = 0x0040;
constexpr uint32_t kBridge = 0x0040;
constexpr uint32_t kTransient = 0x0080;
constexpr uint32_t kVarargs = 0x0080;
constexpr uint32_t kNative = 0x0100;
constexpr uint32_t kInterface = 0x0200;
constexpr uint32_t kAbstract = 0x0400;
constexpr uint32_t kStrict = 0x0800;
constexpr uint32_t kSynthetic = 0x1000;
constexpr uint32_t kEnum = 0x4000;
constexpr uint32_t kConstructor = 0x10000;
constexpr uint32_t kDeclaredSynchronized = 0x20000;
constexpr uint32_t kJavaFlags = 0xFFFF;

constexpr int kMaxValueDepth = 64; // read() refuses deeper values

bool supported_version(uint32_t v) { return v == 35 || v == 37 || v == 38 || v == 39 || v == 40; }

bool at_most_one_visibility(uint32_t flags)
{
    uint32_t v = flags & (kPublic | kPrivate | kProtected);
    return (v & (v - 1)) == 0;
}

bool is_reference(std::string_view type)
{
    return !type.empty() && (type.front() == 'L' || type.front() == '[');
}

// Where a problem is.  Most checks pass, so the text is only built when a
// problem is reported: a large app has millions of instructions.
class Where
{
  public:
    Where(const std::string &base) : base_(&base) {}
    Where(const std::string &base, std::size_t item) : base_(&base), item_(item) {}
    std::string str() const
    {
        return item_ == std::string::npos ? *base_ : std::format("{}, item {}", *base_, item_);
    }

  private:
    const std::string *base_;
    std::size_t item_ = std::string::npos;
};

class Validator
{
  public:
    explicit Validator(const Dex &dex)
        : dex_(dex), version_(supported_version(dex.version) ? dex.version : 40)
    {
    }

    // Names are checked with the 040 rules at every version: ART accepts space
    // characters in names whatever the version (the spec reserves them for
    // 040; Android 10 and older reject them), and apps ship such files.
    static constexpr uint32_t kNameRules = 40;

    /** The lowest DEX version with every feature the model uses, and why. */
    uint32_t needed() const { return needed_; }
    const std::string &needed_reason() const { return needed_reason_; }

    std::vector<Problem> run()
    {
        if (!supported_version(dex_.version))
            problem(kWholeFile, std::format("unsupported DEX version {} (use 35, 37, 38, 39 or 40)",
                                            dex_.version));
        std::unordered_set<std::string_view> types;
        for (const ClassDef &c : dex_.classes)
            if (!types.insert(c.type).second)
                problem(c.type, "the class is defined twice");
        for (const ClassDef &c : dex_.classes)
            check_class(c);
        check_cycles();
        return std::move(problems_);
    }

  private:
    void problem(const Where &where, std::string message)
    {
        problems_.push_back(Problem{where.str(), std::move(message)});
    }

    void need(uint32_t version, const Where &where, std::string_view what)
    {
        if (version > needed_) {
            needed_ = version;
            std::string w = where.str();
            needed_reason_ = w.empty() ? std::string(what) : std::format("{}: {}", w, what);
        }
    }

    static inline const std::string kWholeFile;

    // ----- names, descriptors, references -----

    void check_string(std::string_view s, const Where &where, std::string_view what)
    {
        if (!raw::mutf8::is_valid_wtf8(s))
            problem(where, std::format("{} is not valid UTF-8 / WTF-8", what));
    }
    void check_member_name(std::string_view name, const Where &where)
    {
        if (!raw::is_valid_member_name(name, kNameRules))
            problem(where, std::format("invalid member name \"{}\"", name));
    }
    void check_type(std::string_view type, const Where &where)
    {
        if (!raw::is_valid_type_descriptor(type, kNameRules))
            problem(where, std::format("invalid type descriptor \"{}\"", type));
    }
    void check_field_type(std::string_view type, const Where &where)
    {
        if (!raw::is_valid_field_type(type, kNameRules))
            problem(where, std::format("invalid field type \"{}\"", type));
    }
    void check_class_type(std::string_view type, const Where &where)
    {
        if (!raw::is_valid_class_descriptor(type, kNameRules))
            problem(where, std::format("invalid class descriptor \"{}\"", type));
    }
    void check_proto(std::string_view proto, const Where &where)
    {
        if (!raw::is_valid_proto(proto, kNameRules))
            problem(where, std::format("invalid prototype \"{}\"", proto));
    }
    void check_field_id(const FieldId &f, const Where &where)
    {
        check_class_type(f.class_descriptor, where);
        check_member_name(f.name, where);
        check_field_type(f.type, where);
    }
    void check_method_id(const MethodId &m, const Where &where)
    {
        if (!is_reference(m.class_descriptor) ||
            !raw::is_valid_field_type(m.class_descriptor, kNameRules))
            problem(where, std::format("invalid method class \"{}\"", m.class_descriptor));
        check_member_name(m.name, where);
        check_proto(m.proto, where);
    }
    void check_method_handle(const MethodHandle &h, const Where &where)
    {
        auto kind = static_cast<uint32_t>(h.kind);
        if (kind > 0x08) {
            problem(where, std::format("bad method handle kind {}", kind));
            return;
        }
        bool field_kind = kind <= 0x03;
        if (const FieldId *f = std::get_if<FieldId>(&h.member)) {
            if (!field_kind)
                problem(where, "an invoke method handle names a field");
            check_field_id(*f, where);
        }
        else {
            if (field_kind)
                problem(where, "a field method handle names a method");
            check_method_id(std::get<MethodId>(h.member), where);
        }
    }

    // ----- values and annotations -----

    void check_value(const Value &v, const Where &where, int depth)
    {
        if (depth > kMaxValueDepth) {
            problem(where, "values nest too deeply");
            return;
        }
        std::visit(
            [&](const auto &x) {
                using T = std::decay_t<decltype(x)>;
                if constexpr (std::is_same_v<T, Value::String>)
                    check_string(x.value, where, "a string value");
                else if constexpr (std::is_same_v<T, Value::Type>)
                    check_type(x.descriptor, where);
                else if constexpr (std::is_same_v<T, Value::Field> ||
                                   std::is_same_v<T, Value::Enum>)
                    check_field_id(x.field, where);
                else if constexpr (std::is_same_v<T, Value::Method>)
                    check_method_id(x.method, where);
                else if constexpr (std::is_same_v<T, Value::MethodType>) {
                    need(38, where, "a method type value");
                    check_proto(x.proto, where);
                }
                else if constexpr (std::is_same_v<T, MethodHandle>) {
                    need(38, where, "a method handle value");
                    check_method_handle(x, where);
                }
                else if constexpr (std::is_same_v<T, Value::Array>)
                    for (const Value &e : x.values)
                        check_value(e, where, depth + 1);
                else if constexpr (std::is_same_v<T, Shared<EncodedAnnotation>>)
                    check_encoded_annotation(x.get(), where, depth + 1);
            },
            v.data);
    }

    void check_encoded_annotation(const EncodedAnnotation &a, const Where &where, int depth)
    {
        check_class_type(a.type, where);
        std::unordered_set<std::string_view> names;
        for (const NamedValue &e : a.elements) {
            check_member_name(e.name, where);
            if (!names.insert(e.name).second)
                problem(where,
                        std::format("annotation {} sets element \"{}\" twice", a.type, e.name));
            check_value(e.value, where, depth);
        }
    }

    void check_annotations(const std::vector<AnnotationItem> &set, const Where &where)
    {
        std::unordered_set<std::string_view> types;
        for (const AnnotationItem &a : set) {
            if (static_cast<uint32_t>(a.visibility) > 0x02)
                problem(where, "bad annotation visibility");
            if (!types.insert(a.annotation.type).second)
                problem(where, std::format("annotation {} is present twice", a.annotation.type));
            check_encoded_annotation(a.annotation, where, 0);
        }
    }

    // ----- classes and members -----

    void check_class(const ClassDef &c)
    {
        const Where &where = c.type;
        check_class_type(c.type, where);
        uint32_t flags = static_cast<uint32_t>(c.access);
        if ((flags & ~kJavaFlags) != 0)
            problem(where, std::format("invalid class access flags 0x{:x}", flags));
        if (c.superclass) {
            check_class_type(*c.superclass, where);
            if (*c.superclass == c.type)
                problem(where, "the class is its own superclass");
        }
        else if (c.type != "Ljava/lang/Object;") {
            problem(where, "only java.lang.Object may have no superclass");
        }
        std::unordered_set<std::string_view> interfaces;
        for (const std::string &i : c.interfaces) {
            check_class_type(i, where);
            if (i == c.type)
                problem(where, "the class implements itself");
            if (!interfaces.insert(i).second)
                problem(where, std::format("interface {} is listed twice", i));
        }
        if (c.source_file)
            check_string(*c.source_file, where, "the source file name");
        check_annotations(c.annotations, where);

        std::set<std::pair<std::string_view, std::string_view>> fields, methods;
        for (const FieldDef &f : c.fields) {
            if (!fields.emplace(f.name, f.type).second)
                problem(where, std::format("field {}:{} is defined twice", f.name, f.type));
            check_field(c, f);
        }
        for (const MethodDef &m : c.methods) {
            if (!methods.emplace(m.name, m.proto).second)
                problem(where, std::format("method {}{} is defined twice", m.name, m.proto));
            check_method(c, m);
        }
    }

    void check_field(const ClassDef &c, const FieldDef &f)
    {
        const std::string where = std::format("{}->{}:{}", c.type, f.name, f.type);
        check_member_name(f.name, where);
        check_field_type(f.type, where);
        check_annotations(f.annotations, where);

        // ART's CheckFieldAccessFlags.
        const uint32_t flags = static_cast<uint32_t>(f.access);
        const bool strict = version_ >= 37;
        if ((flags & ~kJavaFlags) != 0)
            problem(where, std::format("invalid field access flags 0x{:x}", flags));
        if (!at_most_one_visibility(flags))
            problem(where, "more than one of public, protected and private");
        if (has(c.access, AccessFlags::Interface)) {
            constexpr uint32_t kPublicFinalStatic = kPublic | kFinal | kStatic;
            constexpr uint32_t kFieldFlags = kPublic | kPrivate | kProtected | kStatic | kFinal |
                                             kVolatile | kTransient | kSynthetic | kEnum;
            if (strict && (flags & kPublicFinalStatic) != kPublicFinalStatic)
                problem(where, "an interface field must be public, static and final");
            if (strict && (flags & kFieldFlags & ~(kPublicFinalStatic | kSynthetic)) != 0)
                problem(where, "an interface field may only be public, static, final, synthetic");
        }
        else if ((flags & (kVolatile | kFinal)) == (kVolatile | kFinal)) {
            problem(where, "a field cannot be both volatile and final");
        }

        if (!f.initial_value)
            return;
        if (!has(f.access, AccessFlags::Static)) {
            problem(where, "only a static field can have an initial value");
            return;
        }
        check_value(*f.initial_value, where, 0);
        // ART's CheckStaticFieldTypes: the value's type must be the field's.
        const char t = f.type.empty() ? '?' : f.type.front();
        bool ok = std::visit(
            [&](const auto &x) {
                using T = std::decay_t<decltype(x)>;
                if constexpr (std::is_same_v<T, Value::Boolean>)
                    return t == 'Z';
                else if constexpr (std::is_same_v<T, Value::Byte>)
                    return t == 'B';
                else if constexpr (std::is_same_v<T, Value::Short>)
                    return t == 'S';
                else if constexpr (std::is_same_v<T, Value::Char>)
                    return t == 'C';
                else if constexpr (std::is_same_v<T, Value::Int>)
                    return t == 'I';
                else if constexpr (std::is_same_v<T, Value::Long>)
                    return t == 'J';
                else if constexpr (std::is_same_v<T, Value::Float>)
                    return t == 'F';
                else if constexpr (std::is_same_v<T, Value::Double>)
                    return t == 'D';
                else if constexpr (std::is_same_v<T, Value::Null> ||
                                   std::is_same_v<T, Value::String> ||
                                   std::is_same_v<T, Value::Type>)
                    return t == 'L' || t == '[';
                else
                    return false;
            },
            f.initial_value->data);
        if (!ok)
            problem(where, "the initial value's type does not match the field's type");
    }

    void check_method(const ClassDef &c, const MethodDef &m)
    {
        const std::string where = std::format("{}->{}{}", c.type, m.name, m.proto);
        check_member_name(m.name, where);
        const bool by_name_init = m.name == "<init>";
        const bool by_name_clinit = m.name == "<clinit>";
        if (!m.name.empty() && m.name.front() == '<' && !by_name_init && !by_name_clinit)
            problem(where, "only <init> and <clinit> may be named in angle brackets");
        check_proto(m.proto, where);
        check_annotations(m.annotations, where);
        for (const auto &set : m.parameter_annotations)
            check_annotations(set, where);

        // ART's CheckMethodAccessFlags and CheckConstructorProperties.
        const uint32_t all = static_cast<uint32_t>(m.access);
        const bool strict = version_ >= 37;
        const bool is_interface = has(c.access, AccessFlags::Interface);
        if ((all & ~(kJavaFlags | kConstructor | kDeclaredSynchronized)) != 0)
            problem(where, std::format("invalid method access flags 0x{:x}", all));
        if (!at_most_one_visibility(all))
            problem(where, "more than one of public, protected and private");
        if ((all & kConstructor) != 0 && !by_name_init && !by_name_clinit)
            problem(where, "only <init> and <clinit> can be marked constructor");
        if (by_name_clinit && (all & kStatic) == 0 && strict)
            problem(where, "<clinit> must be static");
        if (by_name_init && (all & kStatic) != 0 && strict)
            problem(where, "<init> must not be static");
        if (by_name_clinit && m.proto != "()V")
            problem(where, "<clinit> must have the prototype ()V");
        if (by_name_init && !m.proto.ends_with(")V"))
            problem(where, "<init> must return void");

        constexpr uint32_t kMethodFlags = kPublic | kPrivate | kProtected | kStatic | kFinal |
                                          kSynthetic | kSynchronized | kBridge | kVarargs |
                                          kNative | kAbstract | kStrict;
        const uint32_t flags = all & kMethodFlags;
        // ART's method verifier takes private interface members, and the
        // class linker default methods, only from 037.  (Static interface
        // methods are fine in 035 files; apps ship them.)
        if (is_interface && !by_name_clinit &&
            ((flags & kPrivate) != 0 || (m.code && (flags & kStatic) == 0)))
            need(37, where, "a private or default interface method");
        if (is_interface && strict && (flags & (kPublic | kStatic | kPrivate)) == 0)
            problem(where, "an interface method must be public, private or static");
        if (!m.code) {
            if ((flags & (kNative | kAbstract)) == 0)
                problem(where, "a method without code must be abstract or native");
            if ((by_name_init || by_name_clinit) && strict)
                problem(where, "a constructor must have code");
            if ((flags & kAbstract) != 0 &&
                (flags & (kPrivate | kStatic | kFinal | kNative | kStrict | kSynchronized)) != 0)
                problem(where, "an abstract method cannot be private, static, final, native, "
                               "strictfp or synchronized");
            if (is_interface && strict && (flags & (kPublic | kAbstract)) != (kPublic | kAbstract))
                problem(where, "an interface method without code must be public and abstract");
            return;
        }
        if ((flags & (kNative | kAbstract)) != 0)
            problem(where, "an abstract or native method cannot have code");
        if (by_name_init &&
            (flags & ~(kPrivate | kProtected | kPublic | kStrict | kVarargs | kSynthetic)) != 0)
            problem(where, "invalid access flags for <init>");
    }

    // ----- class hierarchy -----

    void check_cycles()
    {
        std::unordered_map<std::string_view, const ClassDef *> by_type;
        for (const ClassDef &c : dex_.classes)
            by_type.emplace(c.type, &c);
        auto supers = [&](const ClassDef *c) {
            std::vector<const ClassDef *> out;
            auto add = [&](std::string_view type) {
                auto it = by_type.find(type);
                if (it != by_type.end())
                    out.push_back(it->second);
            };
            if (c->superclass)
                add(*c->superclass);
            for (const std::string &i : c->interfaces)
                add(i);
            return out;
        };
        // Depth-first search with an explicit stack (a hierarchy can be
        // thousands of classes deep).  A class is on the path while its
        // supertypes are explored; meeting one again closes a cycle.
        enum State : uint8_t { kNew, kOnPath, kDone };
        std::unordered_map<const ClassDef *, State> state;
        std::unordered_set<const ClassDef *> in_cycle;
        for (const ClassDef &root : dex_.classes) {
            if (state[&root] != kNew)
                continue;
            struct Frame
            {
                const ClassDef *cls;
                std::vector<const ClassDef *> next;
                std::size_t i = 0;
            };
            std::vector<Frame> path;
            path.push_back({&root, supers(&root)});
            state[&root] = kOnPath;
            while (!path.empty()) {
                Frame &top = path.back();
                if (top.i == top.next.size()) {
                    state[top.cls] = kDone;
                    path.pop_back();
                    continue;
                }
                const ClassDef *next = top.next[top.i++];
                State &st = state[next];
                if (st == kOnPath) {
                    for (auto it = path.rbegin(); it != path.rend(); ++it) {
                        in_cycle.insert(it->cls);
                        if (it->cls == next)
                            break;
                    }
                }
                else if (st == kNew) {
                    st = kOnPath;
                    path.push_back({next, supers(next)});
                }
            }
        }
        for (const ClassDef &c : dex_.classes)
            if (in_cycle.contains(&c))
                problem(c.type, "the class is part of an inheritance cycle");
    }

    const Dex &dex_;
    const uint32_t version_;
    std::vector<Problem> problems_;
    uint32_t needed_ = 35;
    std::string needed_reason_;
};

} // namespace

std::vector<Problem> validate(const Dex &dex) { return Validator(dex).run(); }

uint32_t required_version(const Dex &dex)
{
    Validator v(dex);
    v.run();
    return v.needed();
}

detail::Checked detail::check(const Dex &dex)
{
    Validator v(dex);
    Checked out;
    out.problems = v.run();
    out.needed_version = v.needed();
    out.needed_reason = v.needed_reason();
    return out;
}

} // namespace dexsplit::model
