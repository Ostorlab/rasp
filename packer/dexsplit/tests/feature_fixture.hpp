#pragma once
#include "model/model.hpp"

namespace dexsplit::test {
/// Reproducible format fixtures exercise actual features, not only changed magic bytes.
inline model::Dex feature_fixture(uint32_t version) {
  model::Dex dex;
  dex.version = version;
  model::ClassDef cls;
  cls.type = version == 40 ? "Lfixture/Space Name;" : "Lfixture/Example;";
  cls.superclass = "Ljava/lang/Object;";
  cls.access = AccessFlags::Public;
  cls.source_file = "Example.java";
  model::MethodDef method;
  method.name = version == 40 ? "with space" : "run";
  method.proto = "()V";
  method.access = AccessFlags::Public | AccessFlags::Static;
  model::Code code;
  code.registers = 2;
  code.items.push_back(model::LineNumber{17});
  code.items.push_back(model::Insn{model::Const{0, 7}});
  if (version == 37) {
    cls.access = AccessFlags::Public | AccessFlags::Interface | AccessFlags::Abstract;
    method.access = AccessFlags::Public;
  }
  if (version == 38) {
    code.items.push_back(model::Insn{model::InvokePolymorphic{
        model::RegList{0},
        MethodId{"Ljava/lang/invoke/MethodHandle;", "invokeExact", "([Ljava/lang/Object;)Ljava/lang/Object;"}, "()V"}});
  }
  if (version == 39) {
    code.items.push_back(model::Insn{model::ConstMethodType{0, "()V"}});
  }
  code.items.push_back(model::Insn{model::ReturnVoid{}});
  method.code = std::move(code);
  cls.methods.push_back(std::move(method));
  if (version != 37) {
    model::FieldDef field;
    field.name = version == 40 ? "field name" : "answer";
    field.type = "I";
    field.access = AccessFlags::Public | AccessFlags::Static;
    field.initial_value = model::Value{model::Value::Int{42}};
    cls.fields.push_back(std::move(field));
  }
  model::AnnotationItem annotation;
  annotation.annotation.type = "Lfixture/Marker;";
  annotation.annotation.elements.push_back({"value", model::Value{model::Value::String{"kept annotation"}}});
  cls.annotations.push_back(std::move(annotation));
  dex.classes.push_back(std::move(cls));
  return dex;
}
}  // namespace dexsplit::test
