#include <format>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "common/budget.hpp"
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
constexpr uint32_t kAbstract = 0x0400;
constexpr uint32_t kStrict = 0x0800;
constexpr uint32_t kSynthetic = 0x1000;
constexpr uint32_t kEnum = 0x4000;
constexpr uint32_t kConstructor = 0x10000;
constexpr uint32_t kDeclaredSynchronized = 0x20000;
constexpr uint32_t kJavaFlags = 0xFFFF;

constexpr int kMaxValueDepth = 64;  // read() refuses deeper values

bool supported_version(uint32_t v) { return v == 35 || v == 37 || v == 38 || v == 39 || v == 40; }

bool at_most_one_visibility(uint32_t flags) {
  uint32_t v = flags & (kPublic | kPrivate | kProtected);
  return (v & (v - 1)) == 0;
}

bool is_reference(std::string_view type) { return !type.empty() && (type.front() == 'L' || type.front() == '['); }

// Unary operations whose destination / source is a register pair.
bool unary_dest_wide(UnaryOp op) {
  switch (op) {
    case UnaryOp::NegLong:
    case UnaryOp::NotLong:
    case UnaryOp::NegDouble:
    case UnaryOp::IntToLong:
    case UnaryOp::IntToDouble:
    case UnaryOp::LongToDouble:
    case UnaryOp::FloatToLong:
    case UnaryOp::FloatToDouble:
    case UnaryOp::DoubleToLong:
      return true;
    default:
      return false;
  }
}
bool unary_src_wide(UnaryOp op) {
  switch (op) {
    case UnaryOp::NegLong:
    case UnaryOp::NotLong:
    case UnaryOp::NegDouble:
    case UnaryOp::LongToInt:
    case UnaryOp::LongToFloat:
    case UnaryOp::LongToDouble:
    case UnaryOp::DoubleToInt:
    case UnaryOp::DoubleToLong:
    case UnaryOp::DoubleToFloat:
      return true;
    default:
      return false;
  }
}
bool binary_wide(BinaryOp op) {
  return (op >= BinaryOp::AddLong && op <= BinaryOp::UshrLong) ||
         (op >= BinaryOp::AddDouble && op <= BinaryOp::RemDouble);
}
bool is_long_shift(BinaryOp op) {
  return op == BinaryOp::ShlLong || op == BinaryOp::ShrLong || op == BinaryOp::UshrLong;
}

// Where a problem is.  Most checks pass, so the text is only built when a
// problem is reported: a large app has millions of instructions.
class Where {
 public:
  Where(const budget::String& base) : base_(&base) {}
  Where(const budget::String& base, std::size_t item) : base_(&base), item_(item) {}
  budget::String str() const {
    return item_ == budget::String::npos ? *base_ : budget::format("{}, item {}", *base_, item_);
  }

 private:
  const budget::String* base_;
  std::size_t item_ = budget::String::npos;
};

class Validator {
 public:
  explicit Validator(const Dex& dex) : dex_(dex), version_(supported_version(dex.version) ? dex.version : 40) {}

  // Names are checked with the 040 rules at every version: ART accepts space
  // characters in names whatever the version (the spec reserves them for
  // 040; Android 10 and older reject them), and apps ship such files.
  static constexpr uint32_t kNameRules = 40;

  /** The lowest DEX version with every feature the model uses, and why. */
  uint32_t needed() const { return needed_; }
  const budget::String& needed_reason() const { return needed_reason_; }

  budget::Vector<Problem> run() {
    if (dex_.classes.size() > budget::kClasses) {
      problem(whole_file_, "DEX class compatibility limit exceeded");
      return std::move(problems_);
    }

    if (!supported_version(dex_.version)) {
      problem(whole_file_, budget::format("unsupported DEX version {} (use 35, 37, 38, 39 or 40)", dex_.version));
    }
    budget::UnorderedSet<std::string_view> types;
    for (const ClassDef& c : dex_.classes) {
      dexsplit::budget::visit();
      if (!types.insert(c.type).second) {
        problem(c.type, "the class is defined twice");
      }
    }
    for (const ClassDef& c : dex_.classes) {
      dexsplit::budget::visit();
      check_class(c);
    }
    check_cycles();
    return std::move(problems_);
  }

 private:
  void problem(const Where& where, budget::String message) {
    if (problems_.size() < 32) {
      problems_.push_back(Problem{where.str(), std::move(message)});
    }
  }

  void need(uint32_t version, const Where& where, std::string_view what) {
    if (version > needed_) {
      needed_ = version;
      budget::String w = where.str();
      needed_reason_ = w.empty() ? budget::String(what) : budget::format("{}: {}", w, what);
    }
  }

  // Instruction operands are shared values: check each once per kind of
  // check (one shared string can be an array type here, a constant there).
  enum Check : uint8_t { kString, kFieldType, kClassType, kArrayType, kProto, kMember, kChecks };
  bool first_check(Check check, const void* shared) { return checked_[check].insert(shared).second; }

  const budget::String whole_file_{budget::Allocator<char>{nullptr}};

  // ----- names, descriptors, references -----

  void check_string(std::string_view s, const Where& where, std::string_view what) {
    if (!raw::mutf8::is_valid_wtf8(s)) {
      problem(where, budget::format("{} is not valid UTF-8 / WTF-8", what));
    }
  }
  void check_member_name(std::string_view name, const Where& where) {
    if (!raw::is_valid_member_name(name, kNameRules)) {
      problem(where, budget::format("invalid member name \"{}\"", name));
    }
  }
  void check_type(std::string_view type, const Where& where) {
    if (!raw::is_valid_type_descriptor(type, kNameRules)) {
      problem(where, budget::format("invalid type descriptor \"{}\"", type));
    }
  }
  void check_field_type(std::string_view type, const Where& where) {
    if (!raw::is_valid_field_type(type, kNameRules)) {
      problem(where, budget::format("invalid field type \"{}\"", type));
    }
  }
  void check_class_type(std::string_view type, const Where& where) {
    if (!raw::is_valid_class_descriptor(type, kNameRules)) {
      problem(where, budget::format("invalid class descriptor \"{}\"", type));
    }
  }
  void check_array_type(std::string_view type, const Where& where) {
    if (type.empty() || type.front() != '[' || !raw::is_valid_field_type(type, kNameRules)) {
      problem(where, budget::format("invalid array type \"{}\"", type));
    }
  }
  void check_proto(std::string_view proto, const Where& where) {
    if (!raw::is_valid_proto(proto, kNameRules)) {
      problem(where, budget::format("invalid prototype \"{}\"", proto));
    }
  }
  void check_field_id(const FieldId& f, const Where& where) {
    check_class_type(f.class_descriptor, where);
    check_member_name(f.name, where);
    check_field_type(f.type, where);
  }
  void check_method_id(const MethodId& m, const Where& where) {
    if (!is_reference(m.class_descriptor) || !raw::is_valid_field_type(m.class_descriptor, kNameRules)) {
      problem(where, budget::format("invalid method class \"{}\"", m.class_descriptor));
    }
    check_member_name(m.name, where);
    check_proto(m.proto, where);
  }
  void check_method_handle(const MethodHandle& h, const Where& where) {
    auto kind = static_cast<uint32_t>(h.kind);
    if (kind > 0x08) {
      problem(where, budget::format("bad method handle kind {}", kind));
      return;
    }
    bool field_kind = kind <= 0x03;
    if (const FieldId* f = std::get_if<FieldId>(&h.member)) {
      if (!field_kind) {
        problem(where, "an invoke method handle names a field");
      }
      check_field_id(*f, where);
    } else {
      if (field_kind) {
        problem(where, "a field method handle names a method");
      }
      check_method_id(std::get<MethodId>(h.member), where);
    }
  }
  void check_call_site(const CallSite& cs, const Where& where) {
    check_method_handle(cs.bootstrap, where);
    check_member_name(cs.method_name, where);
    check_proto(cs.method_type, where);
    for (const Value& v : cs.extra_args) {
      dexsplit::budget::visit();
      check_value(v, where, 0);
    }
  }

  // ----- values and annotations -----

  void check_value(const Value& v, const Where& where, int depth) {
    if (depth > kMaxValueDepth ||
        (depth == kMaxValueDepth &&
         (std::holds_alternative<Value::Array>(v.data) || std::holds_alternative<Shared<EncodedAnnotation>>(v.data)))) {
      problem(where, "values nest too deeply");
      return;
    }
    std::visit(
        [&](const auto& x) {
          using T = std::decay_t<decltype(x)>;
          if constexpr (std::is_same_v<T, Value::String>) {
            check_string(x.value, where, "a string value");
          } else if constexpr (std::is_same_v<T, Value::Type>) {
            check_type(x.descriptor, where);
          } else if constexpr (std::is_same_v<T, Value::Field> || std::is_same_v<T, Value::Enum>) {
            check_field_id(x.field, where);
          } else if constexpr (std::is_same_v<T, Value::Method>) {
            check_method_id(x.method, where);
          } else if constexpr (std::is_same_v<T, Value::MethodType>) {
            need(38, where, "a method type value");
            check_proto(x.proto, where);
          } else if constexpr (std::is_same_v<T, MethodHandle>) {
            need(38, where, "a method handle value");
            check_method_handle(x, where);
          } else if constexpr (std::is_same_v<T, Value::Array>) {
            for (const Value& e : x.values) {
              dexsplit::budget::visit();
              check_value(e, where, depth + 1);
            }
          } else if constexpr (std::is_same_v<T, Shared<EncodedAnnotation>>) {
            check_encoded_annotation(x.get(), where, depth + 1);
          }
        },
        v.data);
  }

  void check_encoded_annotation(const EncodedAnnotation& a, const Where& where, int depth) {
    check_class_type(a.type, where);
    budget::UnorderedSet<std::string_view> names;
    for (const NamedValue& e : a.elements) {
      dexsplit::budget::visit();
      check_member_name(e.name, where);
      if (!names.insert(e.name).second) {
        problem(where, budget::format("annotation {} sets element \"{}\" twice", a.type, e.name));
      }
      check_value(e.value, where, depth);
    }
  }

  void check_annotations(const budget::Vector<AnnotationItem>& set, const Where& where) {
    budget::UnorderedSet<std::string_view> types;
    for (const AnnotationItem& a : set) {
      dexsplit::budget::visit();
      if (static_cast<uint32_t>(a.visibility) > 0x02) {
        problem(where, "bad annotation visibility");
      }
      if (!types.insert(a.annotation.type).second) {
        problem(where, budget::format("annotation {} is present twice", a.annotation.type));
      }
      check_encoded_annotation(a.annotation, where, 0);
    }
  }

  // ----- classes and members -----

  void check_class(const ClassDef& c) {
    const Where& where = c.type;
    check_class_type(c.type, where);
    uint32_t flags = static_cast<uint32_t>(c.access);
    if ((flags & ~kJavaFlags) != 0) {
      problem(where, budget::format("invalid class access flags 0x{:x}", flags));
    }
    if (c.superclass) {
      check_class_type(*c.superclass, where);
      if (*c.superclass == c.type) {
        problem(where, "the class is its own superclass");
      }
    } else if (c.type != "Ljava/lang/Object;") {
      problem(where, "only java.lang.Object may have no superclass");
    }
    budget::UnorderedSet<std::string_view> interfaces;
    for (const budget::String& i : c.interfaces) {
      dexsplit::budget::visit();
      check_class_type(i, where);
      if (i == c.type) {
        problem(where, "the class implements itself");
      }
      if (!interfaces.insert(i).second) {
        problem(where, budget::format("interface {} is listed twice", i));
      }
    }
    if (c.source_file) {
      check_string(*c.source_file, where, "the source file name");
    }
    check_annotations(c.annotations, where);

    budget::Set<std::pair<std::string_view, std::string_view>> fields, methods;
    for (const FieldDef& f : c.fields) {
      dexsplit::budget::visit();
      if (!fields.emplace(f.name, f.type).second) {
        problem(where, budget::format("field {}:{} is defined twice", f.name, f.type));
      }
      check_field(c, f);
    }
    for (const MethodDef& m : c.methods) {
      dexsplit::budget::visit();
      if (!methods.emplace(m.name, m.proto).second) {
        problem(where, budget::format("method {}{} is defined twice", m.name, m.proto));
      }
      check_method(c, m);
    }
  }

  void check_field(const ClassDef& c, const FieldDef& f) {
    const budget::String where = budget::format("{}->{}:{}", c.type, f.name, f.type);
    check_member_name(f.name, where);
    check_field_type(f.type, where);
    check_annotations(f.annotations, where);

    // ART's CheckFieldAccessFlags.
    const uint32_t flags = static_cast<uint32_t>(f.access);
    const bool strict = version_ >= 37;
    if ((flags & ~kJavaFlags) != 0) {
      problem(where, budget::format("invalid field access flags 0x{:x}", flags));
    }
    if (!at_most_one_visibility(flags)) {
      problem(where, "more than one of public, protected and private");
    }
    if (has(c.access, AccessFlags::Interface)) {
      constexpr uint32_t kPublicFinalStatic = kPublic | kFinal | kStatic;
      constexpr uint32_t kFieldFlags =
          kPublic | kPrivate | kProtected | kStatic | kFinal | kVolatile | kTransient | kSynthetic | kEnum;
      if (strict && (flags & kPublicFinalStatic) != kPublicFinalStatic) {
        problem(where, "an interface field must be public, static and final");
      }
      if (strict && (flags & kFieldFlags & ~(kPublicFinalStatic | kSynthetic)) != 0) {
        problem(where, "an interface field may only be public, static, final, synthetic");
      }
    } else if ((flags & (kVolatile | kFinal)) == (kVolatile | kFinal)) {
      problem(where, "a field cannot be both volatile and final");
    }

    if (!f.initial_value) {
      return;
    }
    if (!has(f.access, AccessFlags::Static)) {
      problem(where, "only a static field can have an initial value");
      return;
    }
    check_value(*f.initial_value, where, 0);
    // ART's CheckStaticFieldTypes: the value's type must be the field's.
    const char t = f.type.empty() ? '?' : f.type.front();
    bool ok = std::visit(
        [&](const auto& x) {
          using T = std::decay_t<decltype(x)>;
          if constexpr (std::is_same_v<T, Value::Boolean>) {
            return t == 'Z';
          } else if constexpr (std::is_same_v<T, Value::Byte>) {
            return t == 'B';
          } else if constexpr (std::is_same_v<T, Value::Short>) {
            return t == 'S';
          } else if constexpr (std::is_same_v<T, Value::Char>) {
            return t == 'C';
          } else if constexpr (std::is_same_v<T, Value::Int>) {
            return t == 'I';
          } else if constexpr (std::is_same_v<T, Value::Long>) {
            return t == 'J';
          } else if constexpr (std::is_same_v<T, Value::Float>) {
            return t == 'F';
          } else if constexpr (std::is_same_v<T, Value::Double>) {
            return t == 'D';
          } else if constexpr (std::is_same_v<T, Value::Null> || std::is_same_v<T, Value::String> ||
                               std::is_same_v<T, Value::Type>) {
            return t == 'L' || t == '[';
          } else {
            return false;
          }
        },
        f.initial_value->data);
    if (!ok) {
      problem(where, "the initial value's type does not match the field's type");
    }
  }

  void check_method(const ClassDef& c, const MethodDef& m) {
    const budget::String where = budget::format("{}->{}{}", c.type, m.name, m.proto);
    check_member_name(m.name, where);
    const bool by_name_init = m.name == "<init>";
    const bool by_name_clinit = m.name == "<clinit>";
    if (!m.name.empty() && m.name.front() == '<' && !by_name_init && !by_name_clinit) {
      problem(where, "only <init> and <clinit> may be named in angle brackets");
    }
    check_proto(m.proto, where);
    check_annotations(m.annotations, where);
    for (const auto& set : m.parameter_annotations) {
      dexsplit::budget::visit();
      check_annotations(set, where);
    }

    // ART's CheckMethodAccessFlags and CheckConstructorProperties.
    const uint32_t all = static_cast<uint32_t>(m.access);
    const bool strict = version_ >= 37;
    const bool is_interface = has(c.access, AccessFlags::Interface);
    if ((all & ~(kJavaFlags | kConstructor | kDeclaredSynchronized)) != 0) {
      problem(where, budget::format("invalid method access flags 0x{:x}", all));
    }
    if (!at_most_one_visibility(all)) {
      problem(where, "more than one of public, protected and private");
    }
    if ((all & kConstructor) != 0 && !by_name_init && !by_name_clinit) {
      problem(where, "only <init> and <clinit> can be marked constructor");
    }
    if (by_name_clinit && (all & kStatic) == 0 && strict) {
      problem(where, "<clinit> must be static");
    }
    if (by_name_init && (all & kStatic) != 0 && strict) {
      problem(where, "<init> must not be static");
    }
    if (by_name_clinit && m.proto != "()V") {
      problem(where, "<clinit> must have the prototype ()V");
    }
    if (by_name_init && !m.proto.ends_with(")V")) {
      problem(where, "<init> must return void");
    }

    constexpr uint32_t kMethodFlags = kPublic | kPrivate | kProtected | kStatic | kFinal | kSynthetic | kSynchronized |
                                      kBridge | kVarargs | kNative | kAbstract | kStrict;
    const uint32_t flags = all & kMethodFlags;
    // ART's method verifier takes private interface members, and the
    // class linker default methods, only from 037.  (Static interface
    // methods are fine in 035 files; apps ship them.)
    if (is_interface && !by_name_clinit && ((flags & kPrivate) != 0 || (m.code && (flags & kStatic) == 0))) {
      need(37, where, "a private or default interface method");
    }
    if (is_interface && strict && (flags & (kPublic | kStatic | kPrivate)) == 0) {
      problem(where, "an interface method must be public, private or static");
    }
    if (!m.code) {
      if ((flags & (kNative | kAbstract)) == 0) {
        problem(where, "a method without code must be abstract or native");
      }
      if ((by_name_init || by_name_clinit) && strict) {
        problem(where, "a constructor must have code");
      }
      if ((flags & kAbstract) != 0 &&
          (flags & (kPrivate | kStatic | kFinal | kNative | kStrict | kSynchronized)) != 0) {
        problem(where,
                "an abstract method cannot be private, static, final, native, "
                "strictfp or synchronized");
      }
      if (is_interface && strict && (flags & (kPublic | kAbstract)) != (kPublic | kAbstract)) {
        problem(where, "an interface method without code must be public and abstract");
      }
      return;
    }
    if ((flags & (kNative | kAbstract)) != 0) {
      problem(where, "an abstract or native method cannot have code");
    }
    if (by_name_init && (flags & ~(kPrivate | kProtected | kPublic | kStrict | kVarargs | kSynthetic)) != 0) {
      problem(where, "invalid access flags for <init>");
    }
    check_code(m, *m.code, where);
  }

  // ----- code -----

  void check_code(const MethodDef& m, const Code& code, const budget::String& method) {
    const budget::Vector<Item>& items = code.items;
    auto at = [&](std::size_t i) { return Where(method, i); };

    if (raw::is_valid_proto(m.proto, kNameRules) && code.registers < detail::ins_words(m)) {
      problem(method,
              budget::format("{} registers cannot hold the {} argument words", code.registers, detail::ins_words(m)));
    }
    bool any_insn = false;
    budget::UnorderedMap<uint32_t, std::pair<std::size_t, bool>> placed;
    for (std::size_t i = items.size(); i-- > 0;) {
      budget::visit();
      any_insn = any_insn || std::holds_alternative<Insn>(items[i]);
      if (const auto* label = std::get_if<Label>(&items[i])) {
        if (!placed.emplace(label->id, std::pair{i, any_insn}).second) {
          problem(at(i), budget::format("label {} is placed twice", label->id));
        }
      }
    }
    if (!any_insn) {
      problem(method, "the code has no instructions");
    }
    auto jump_target = [&](Label l, const Where& where) {
      auto it = placed.find(l.id);
      if (it == placed.end()) {
        problem(where, budget::format("label {} is not placed", l.id));
      } else if (!it->second.second) {
        problem(where, budget::format("label {} is not followed by an instruction", l.id));
      }
    };

    for (std::size_t k = 0; k < code.tries.size(); ++k) {
      dexsplit::budget::visit();
      const TryRange& t = code.tries[k];
      const budget::String where = budget::format("{}, try range {}", method, k);
      auto start = placed.find(t.start.id);
      auto end = placed.find(t.end.id);
      if (start == placed.end() || end == placed.end()) {
        problem(where, "a try range label is not placed");
      } else if (start->second.first > end->second.first) {
        problem(where, "the try range ends before it starts");
      }
      for (const Catch& c : t.catches) {
        dexsplit::budget::visit();
        check_class_type(c.type, where);
        jump_target(c.handler, where);
      }
      if (t.catch_all) {
        jump_target(*t.catch_all, where);
      }
    }

    for (const auto& name : code.parameter_names) {
      dexsplit::budget::visit();
      if (name) {
        check_string(*name, method, "a parameter name");
      }
    }

    budget::Vector<uint8_t> local_state(code.registers, 0);
    if (auto prototype = raw::parse_proto(m.proto); prototype && detail::ins_words(m) <= code.registers) {
      uint32_t reg = code.registers - detail::ins_words(m);
      if ((static_cast<uint32_t>(m.access) & kStatic) == 0) {
        local_state[reg++] = 1;
      }
      for (const auto& parameter : prototype->params) {
        budget::visit();
        local_state[reg] = 1;
        reg += parameter == "J" || parameter == "D" ? 2 : 1;
      }
    }
    auto local_register = [&](Reg reg, const Where& where) {
      if (reg >= code.registers) {
        problem(where, "debug local register is outside the frame");
        return false;
      }
      return true;
    };
    for (std::size_t i = 0; i < items.size(); ++i) {
      dexsplit::budget::visit();
      const Item& item = items[i];
      if (const Insn* insn = std::get_if<Insn>(&item)) {
        check_insn(*insn, code, at(i), jump_target);
      } else if (const LocalStart* s = std::get_if<LocalStart>(&item)) {
        if (local_register(s->reg, at(i))) {
          local_state[s->reg] = 1;
        }
        const LocalVariable& v = s->local.get();
        if (v.name) {
          check_string(*v.name, at(i), "a local variable name");
        }
        if (v.type) {
          check_field_type(*v.type, at(i));
        }
        if (v.signature) {
          check_string(*v.signature, at(i), "a local variable signature");
        }
      } else if (const LocalEnd* end = std::get_if<LocalEnd>(&item)) {
        if (local_register(end->reg, at(i))) {
          if (local_state[end->reg] == 1) {
            local_state[end->reg] = 2;
          }
        }
      } else if (const LocalRestart* restart = std::get_if<LocalRestart>(&item)) {
        if (local_register(restart->reg, at(i))) {
          if (local_state[restart->reg] == 0) {
            problem(at(i), "debug local restart has no known local metadata");
          }
          local_state[restart->reg] = 1;
        }
      } else if (const SetSourceFile* f = std::get_if<SetSourceFile>(&item)) {
        if (f->name) {
          check_string(*f->name, at(i), "a source file name");
        }
      }
    }
  }

  template <class JumpTarget>
  void check_insn(const Insn& insn, const Code& code, const Where& where, JumpTarget& jump_target) {
    // A register operand: below `limit` for the instruction to be
    // encodable, and inside the frame (both halves of a pair).
    auto reg = [&](Reg r, bool wide, uint32_t limit) {
      if (r >= limit) {
        problem(where, budget::format("v{} does not fit the instruction (needs v{} or lower)", r, limit - 1));
      }
      if (uint32_t{r} + (wide ? 1 : 0) >= code.registers) {
        problem(where, budget::format("v{}{} is outside the {} registers of the frame", r, wide ? " (pair)" : "",
                                      code.registers));
      }
    };
    auto args = [&](const RegList& list) {
      if (!detail::args_encodable(list)) {
        problem(where,
                "argument registers must be at most five below v16, or a run of at "
                "most 255");
      }
      for (Reg r : list) {
        dexsplit::budget::visit();
        reg(r, false, 0x10000);
      }
    };
    auto mover_kind = [&](ValueKind k) {
      if (k != ValueKind::Normal && k != ValueKind::Wide && k != ValueKind::Object) {
        problem(where, "this instruction only takes the Normal, Wide or Object kind");
      }
    };
    auto wide = [](ValueKind k) { return k == ValueKind::Wide; };

    std::visit(
        [&](const auto& x) {
          using T = std::decay_t<decltype(x)>;
          if constexpr (std::is_same_v<T, Move>) {
            mover_kind(x.kind);
            reg(x.dest, wide(x.kind), 0x10000);
            reg(x.src, wide(x.kind), 0x10000);
          } else if constexpr (std::is_same_v<T, MoveResult>) {
            mover_kind(x.kind);
            reg(x.dest, wide(x.kind), 256);
          } else if constexpr (std::is_same_v<T, MoveException> || std::is_same_v<T, Const>) {
            reg(x.dest, false, 256);
          } else if constexpr (std::is_same_v<T, Return>) {
            mover_kind(x.kind);
            reg(x.src, wide(x.kind), 256);

          } else if constexpr (std::is_same_v<T, ConstWide>) {
            reg(x.dest, true, 256);
          } else if constexpr (std::is_same_v<T, ConstString>) {
            reg(x.dest, false, 256);
            if (first_check(kString, &x.value.get())) {
              check_string(x.value.get(), where, "the string constant");
            }
          } else if constexpr (std::is_same_v<T, ConstClass>) {
            reg(x.dest, false, 256);
            if (first_check(kFieldType, &x.type.get())) {
              check_field_type(x.type.get(), where);
            }
          } else if constexpr (std::is_same_v<T, ConstMethodHandle>) {
            need(39, where, "const-method-handle");
            reg(x.dest, false, 256);
            if (first_check(kMember, &x.handle.get())) {
              check_method_handle(x.handle.get(), where);
            }
          } else if constexpr (std::is_same_v<T, ConstMethodType>) {
            need(39, where, "const-method-type");
            reg(x.dest, false, 256);
            if (first_check(kProto, &x.proto.get())) {
              check_proto(x.proto.get(), where);
            }
          } else if constexpr (std::is_same_v<T, MonitorEnter> || std::is_same_v<T, MonitorExit>) {
            reg(x.object, false, 256);
          } else if constexpr (std::is_same_v<T, CheckCast>) {
            reg(x.object, false, 256);
            if (first_check(kFieldType, &x.type.get())) {
              check_field_type(x.type.get(), where);
            }
          } else if constexpr (std::is_same_v<T, InstanceOf>) {
            reg(x.dest, false, 16);
            reg(x.object, false, 16);
            if (first_check(kFieldType, &x.type.get())) {
              check_field_type(x.type.get(), where);
            }
          } else if constexpr (std::is_same_v<T, ArrayLength>) {
            reg(x.dest, false, 16);
            reg(x.array, false, 16);
          } else if constexpr (std::is_same_v<T, NewInstance>) {
            reg(x.dest, false, 256);
            if (first_check(kClassType, &x.type.get())) {
              check_class_type(x.type.get(), where);
            }
          } else if constexpr (std::is_same_v<T, NewArray>) {
            reg(x.dest, false, 16);
            reg(x.size, false, 16);
            if (first_check(kArrayType, &x.type.get())) {
              check_array_type(x.type.get(), where);
            }
          } else if constexpr (std::is_same_v<T, FilledNewArray>) {
            args(x.args);
            if (first_check(kArrayType, &x.type.get())) {
              check_array_type(x.type.get(), where);
            }
          } else if constexpr (std::is_same_v<T, FillArrayData>) {
            reg(x.array, false, 256);
            uint16_t w = x.element_width;
            if (w != 1 && w != 2 && w != 4 && w != 8) {
              problem(where, "fill-array-data elements must be 1, 2, 4 or 8 bytes wide");
            } else if (x.data.size() % w != 0 || x.data.size() / w > UINT32_MAX) {
              problem(where, "fill-array-data holds a partial element");
            }
          } else if constexpr (std::is_same_v<T, Throw>) {
            reg(x.exception, false, 256);
          } else if constexpr (std::is_same_v<T, Goto>) {
            jump_target(x.target, where);
          } else if constexpr (std::is_same_v<T, Switch>) {
            reg(x.value, false, 256);
            if (x.cases.size() > 0xFFFF) {
              problem(where, "a switch has at most 65535 cases");
            }
            budget::UnorderedSet<int32_t> keys;
            for (const Switch::Case& c : x.cases) {
              dexsplit::budget::visit();
              if (!keys.insert(c.key).second) {
                problem(where, budget::format("switch key {} is listed twice", c.key));
              }
              jump_target(c.target, where);
            }
          } else if constexpr (std::is_same_v<T, Compare>) {
            bool w = x.op != CompareOp::CmplFloat && x.op != CompareOp::CmpgFloat;
            reg(x.dest, false, 256);
            reg(x.a, w, 256);
            reg(x.b, w, 256);
          } else if constexpr (std::is_same_v<T, If>) {
            reg(x.a, false, 16);
            reg(x.b, false, 16);
            jump_target(x.target, where);
          } else if constexpr (std::is_same_v<T, IfZero>) {
            reg(x.value, false, 256);
            jump_target(x.target, where);
          } else if constexpr (std::is_same_v<T, ArrayGet> || std::is_same_v<T, ArrayPut>) {
            if constexpr (std::is_same_v<T, ArrayGet>) {
              reg(x.dest, wide(x.kind), 256);
            } else {
              reg(x.value, wide(x.kind), 256);
            }
            reg(x.array, false, 256);
            reg(x.index, false, 256);
          } else if constexpr (std::is_same_v<T, InstanceGet> || std::is_same_v<T, InstancePut>) {
            if constexpr (std::is_same_v<T, InstanceGet>) {
              reg(x.dest, wide(x.kind), 16);
            } else {
              reg(x.value, wide(x.kind), 16);
            }
            reg(x.object, false, 16);
            if (first_check(kMember, &x.field.get())) {
              check_field_id(x.field.get(), where);
            }
          } else if constexpr (std::is_same_v<T, StaticGet> || std::is_same_v<T, StaticPut>) {
            if constexpr (std::is_same_v<T, StaticGet>) {
              reg(x.dest, wide(x.kind), 256);
            } else {
              reg(x.value, wide(x.kind), 256);
            }
            if (first_check(kMember, &x.field.get())) {
              check_field_id(x.field.get(), where);
            }
          } else if constexpr (std::is_same_v<T, Invoke>) {
            if (static_cast<uint32_t>(x.kind) > 4) {
              problem(where, "bad invoke kind");
            }
            args(x.args);
            if (first_check(kMember, &x.method.get())) {
              check_method_id(x.method.get(), where);
            }
          } else if constexpr (std::is_same_v<T, InvokePolymorphic>) {
            need(38, where, "invoke-polymorphic");
            args(x.args);
            if (first_check(kMember, &x.method.get())) {
              check_method_id(x.method.get(), where);
            }
            if (first_check(kProto, &x.proto.get())) {
              check_proto(x.proto.get(), where);
            }
          } else if constexpr (std::is_same_v<T, InvokeCustom>) {
            need(38, where, "invoke-custom");
            args(x.args);
            if (first_check(kMember, &x.call_site.get())) {
              check_call_site(x.call_site.get(), where);
            }
          } else if constexpr (std::is_same_v<T, Unary>) {
            reg(x.dest, unary_dest_wide(x.op), 16);
            reg(x.src, unary_src_wide(x.op), 16);
          } else if constexpr (std::is_same_v<T, Binary>) {
            bool w = binary_wide(x.op);
            reg(x.dest, w, 256);
            reg(x.a, w, 256);
            reg(x.b, w && !is_long_shift(x.op), 256);
          } else if constexpr (std::is_same_v<T, BinaryLiteral>) {
            bool lit8 = x.literal >= -128 && x.literal <= 127;
            bool shift = x.op == LiteralOp::Shl || x.op == LiteralOp::Shr || x.op == LiteralOp::Ushr;
            if (shift && !lit8) {
              problem(where, "a shift by a literal takes an 8-bit literal");
            }
            uint32_t limit = lit8 ? 256 : 16;
            reg(x.dest, false, limit);
            reg(x.src, false, limit);
          }
        },
        insn);
  }

  // ----- class hierarchy -----

  void check_cycles() {
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
    // Depth-first search with an explicit stack (a hierarchy can be
    // thousands of classes deep).  A class is on the path while its
    // supertypes are explored; meeting one again closes a cycle.
    enum State : uint8_t { kNew, kOnPath, kDone };
    budget::UnorderedMap<const ClassDef*, State> state;
    budget::UnorderedSet<const ClassDef*> in_cycle;
    for (const ClassDef& root : dex_.classes) {
      dexsplit::budget::visit();
      if (state[&root] != kNew) {
        continue;
      }
      struct Frame {
        const ClassDef* cls;
        budget::Vector<const ClassDef*> next;
        std::size_t i = 0;
      };
      budget::Vector<Frame> path;
      path.push_back({&root, supers(&root)});
      state[&root] = kOnPath;
      while (!path.empty()) {
        dexsplit::budget::visit();
        Frame& top = path.back();
        if (top.i == top.next.size()) {
          state[top.cls] = kDone;
          path.pop_back();
          continue;
        }
        const ClassDef* next = top.next[top.i++];
        State& st = state[next];
        if (st == kOnPath) {
          for (auto it = path.rbegin(); it != path.rend(); ++it) {
            dexsplit::budget::visit();
            in_cycle.insert(it->cls);
            if (it->cls == next) {
              break;
            }
          }
        } else if (st == kNew) {
          st = kOnPath;
          path.push_back({next, supers(next)});
        }
      }
    }
    for (const ClassDef& c : dex_.classes) {
      dexsplit::budget::visit();
      if (in_cycle.contains(&c)) {
        problem(c.type, "the class is part of an inheritance cycle");
      }
    }
  }

  const Dex& dex_;
  const uint32_t version_;
  budget::Vector<Problem> problems_;
  budget::UnorderedSet<const void*> checked_[kChecks];
  uint32_t needed_ = 35;
  budget::String needed_reason_;
};

}  // namespace

budget::Vector<Problem> validate(const Dex& dex) {
  budget::Scope scope(dex.request);
  return Validator(dex).run();
}

uint32_t required_version(const Dex& dex) {
  budget::Scope scope(dex.request);
  Validator v(dex);
  v.run();
  return v.needed();
}

detail::Checked detail::check(const Dex& dex) {
  Validator v(dex);
  Checked out;
  out.problems = v.run();
  out.needed_version = v.needed();
  out.needed_reason = v.needed_reason();
  return out;
}

}  // namespace dexsplit::model
