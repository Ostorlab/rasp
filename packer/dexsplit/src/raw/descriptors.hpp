#include "common/budget.hpp"
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/** The DEX format's string syntax for names and type descriptors, and helpers
 *  for building and splitting descriptors.
 *
 *  Strings are WTF-8 (see raw/mutf8.hpp).  Rules that changed between DEX
 *  versions take the version as a number (35, 37, 38, 39 or 40): space
 *  characters are allowed in names only from version 040. */
namespace dexsplit::raw {

/** True if @p name is a SimpleName: one or more name characters. */
bool is_valid_simple_name(std::string_view name, uint32_t dex_version);

/** True if @p name is a MemberName: a SimpleName, or '<' SimpleName '>'.
 *  (Method names in angle brackets are further limited to "<init>" and
 *  "<clinit>"; that rule belongs to methods, not to the syntax.) */
bool is_valid_member_name(std::string_view name, uint32_t dex_version);

/** True if @p descriptor is a TypeDescriptor: 'V', a primitive, a class
 *  'L' FullClassName ';', or an array of 1 to 255 dimensions of a non-void
 *  type. */
bool is_valid_type_descriptor(std::string_view descriptor, uint32_t dex_version);

/** True if @p descriptor is a class descriptor: 'L' FullClassName ';'. */
bool is_valid_class_descriptor(std::string_view descriptor, uint32_t dex_version);

/** True if @p descriptor is a type a value can have: any TypeDescriptor but 'V'. */
bool is_valid_field_type(std::string_view descriptor, uint32_t dex_version);

/** A method prototype "(" parameters ")" return-type, split into parts.  The
 *  views point into the descriptor that was parsed. */
struct ProtoParts {
  budget::Vector<std::string_view> params;
  std::string_view return_type;
};

/** Split @p proto into its parameter and return types.  Returns nullopt if it
 *  is not of the form "(" field-types ")" type, where each part has the
 *  shape of a descriptor.  Names inside the parts are not checked; use
 *  is_valid_proto() for that. */
std::optional<ProtoParts> parse_proto(std::string_view proto);

/** True if @p proto is a valid method prototype: every parameter a valid
 *  field type, the return type a valid type descriptor. */
bool is_valid_proto(std::string_view proto, uint32_t dex_version);

/** Build the prototype descriptor "(" params... ")" return_type. */
budget::String make_proto(std::span<const budget::String> params, std::string_view return_type);
budget::String make_proto(std::initializer_list<std::string_view> params, std::string_view return_type);

/** The shorty of a valid prototype: the return type then each parameter, as
 *  one character each, with every class and array type written as 'L'.
 *  E.g. "(ILjava/lang/String;[J)V" -> "VILL". */
budget::String shorty_of(std::string_view proto);

/** Number of registers the parameters of a valid prototype take: two for
 *  long and double ('J', 'D'), one for everything else. */
uint32_t parameter_words(std::string_view proto);

/** The descriptor of a class given its binary name: "java.lang.String" ->
 *  "Ljava/lang/String;", "a.Outer$Inner" -> "La/Outer$Inner;". */
budget::String descriptor_of_class(std::string_view binary_name);

/** The Java name of a type, as java.lang.Class.getName() spells it:
 *  "Ljava/lang/String;" -> "java.lang.String", "I" -> "int",
 *  "[Ljava/lang/String;" -> "[Ljava.lang.String;". */
budget::String java_name_of(std::string_view descriptor);

}  // namespace dexsplit::raw
