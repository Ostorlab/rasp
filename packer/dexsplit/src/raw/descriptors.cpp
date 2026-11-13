#include "raw/descriptors.hpp"

#include "common/budget.hpp"
#include "raw/mutf8.hpp"

namespace dexsplit::raw {

namespace {

bool is_high_surrogate(uint32_t u) { return u >= 0xD800 && u <= 0xDBFF; }
bool is_low_surrogate(uint32_t u) { return u >= 0xDC00 && u <= 0xDFFF; }

// SimpleNameChar from the DEX format's string syntax.  Space characters
// (Unicode category Zs) are allowed from version 040.
enum class NameSyntax : uint8_t { Basic, Spaces };

bool is_name_char(uint32_t cp, NameSyntax syntax) {
  if ((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9')) {
    return true;
  }
  if (cp == '$' || cp == '-' || cp == '_') {
    return true;
  }
  if (cp == ' ' || cp == 0xA0 || (cp >= 0x2000 && cp <= 0x200A) || cp == 0x202F) {
    return syntax == NameSyntax::Spaces;
  }
  return (cp >= 0xA1 && cp <= 0x1FFF) || (cp >= 0x2010 && cp <= 0x2027) || (cp >= 0x2030 && cp <= 0xD7FF) ||
         (cp >= 0xE000 && cp <= 0xFFEF) || (cp >= 0x10000 && cp <= 0x10FFFF);
}

// One field type at the start of @p s ('['* then a primitive or 'L'...';'),
// checked for shape only.  Returns its length, or 0 if there is none.
std::size_t field_type_length(std::string_view s) {
  std::size_t pos = 0;
  while (pos < s.size() && s[pos] == '[') {
    ++pos;
  }
  if (pos >= s.size()) {
    return 0;
  }
  switch (s[pos]) {
    case 'Z':
    case 'B':
    case 'S':
    case 'C':
    case 'I':
    case 'J':
    case 'F':
    case 'D':
      return pos + 1;
    case 'L': {
      std::size_t end = s.find(';', pos);
      return end == std::string_view::npos ? 0 : end + 1;
    }
    default:
      return 0;
  }
}

bool is_valid_class_name(std::string_view name, uint32_t dex_version) {
  // FullClassName: (SimpleName '/')* SimpleName
  std::size_t start = 0;
  while (true) {
    std::size_t slash = name.find('/', start);
    std::string_view part = name.substr(start, slash - start);
    if (!is_valid_simple_name(part, dex_version)) {
      return false;
    }
    if (slash == std::string_view::npos) {
      return true;
    }
    start = slash + 1;
  }
}

}  // namespace

bool is_valid_simple_name(std::string_view name, uint32_t dex_version) {
  if (name.empty() || !mutf8::is_valid_wtf8(name)) {
    return false;
  }
  std::size_t pos = 0;
  while (pos < name.size()) {
    uint32_t cp = mutf8::next_code_point(name, pos);
    // A surrogate pair written as two 3-byte sequences is the same DEX
    // string as its 4-byte form, so it counts as one character.
    if (is_high_surrogate(cp) && pos < name.size()) {
      std::size_t after = pos;
      uint32_t lo = mutf8::next_code_point(name, after);
      if (is_low_surrogate(lo)) {
        cp = 0x10000U + ((cp - 0xD800U) << 10U) + (lo - 0xDC00U);
        pos = after;
      }
    }
    if (!is_name_char(cp, dex_version >= 40 ? NameSyntax::Spaces : NameSyntax::Basic)) {
      return false;
    }
  }
  return true;
}

bool is_valid_member_name(std::string_view name, uint32_t dex_version) {
  if (name.size() >= 2 && name.front() == '<' && name.back() == '>') {
    return is_valid_simple_name(name.substr(1, name.size() - 2), dex_version);
  }
  return is_valid_simple_name(name, dex_version);
}

bool is_valid_type_descriptor(std::string_view descriptor, uint32_t dex_version) {
  std::size_t dims = 0;
  while (dims < descriptor.size() && descriptor[dims] == '[') {
    ++dims;
  }
  if (dims > 255) {
    return false;
  }
  std::string_view element = descriptor.substr(dims);
  if (element.size() == 1) {
    switch (element[0]) {
      case 'Z':
      case 'B':
      case 'S':
      case 'C':
      case 'I':
      case 'J':
      case 'F':
      case 'D':
        return true;
      case 'V':
        return dims == 0;
      default:
        return false;
    }
  }
  return element.size() >= 3 && element.front() == 'L' && element.back() == ';' &&
         is_valid_class_name(element.substr(1, element.size() - 2), dex_version);
}

bool is_valid_class_descriptor(std::string_view descriptor, uint32_t dex_version) {
  return !descriptor.empty() && descriptor.front() == 'L' && is_valid_type_descriptor(descriptor, dex_version);
}

bool is_valid_field_type(std::string_view descriptor, uint32_t dex_version) {
  return descriptor != "V" && is_valid_type_descriptor(descriptor, dex_version);
}

std::optional<ProtoParts> parse_proto(std::string_view proto) {
  if (proto.empty() || proto.front() != '(') {
    return std::nullopt;
  }
  ProtoParts parts;
  std::size_t pos = 1;
  while (true) {
    if (pos >= proto.size()) {
      return std::nullopt;
    }
    if (proto[pos] == ')') {
      break;
    }
    std::size_t len = field_type_length(proto.substr(pos));
    if (len == 0) {
      return std::nullopt;
    }
    parts.params.push_back(proto.substr(pos, len));
    pos += len;
  }
  std::string_view ret = proto.substr(pos + 1);
  if (ret != "V" && field_type_length(ret) != ret.size()) {
    return std::nullopt;
  }
  if (ret.empty()) {
    return std::nullopt;
  }
  parts.return_type = ret;
  return parts;
}

bool is_valid_proto(std::string_view proto, uint32_t dex_version) {
  auto parts = parse_proto(proto);
  if (!parts || !is_valid_type_descriptor(parts->return_type, dex_version)) {
    return false;
  }
  for (std::string_view p : parts->params) {
    if (!is_valid_field_type(p, dex_version)) {
      return false;
    }
  }
  return true;
}

budget::String make_proto(std::span<const budget::String> params, std::string_view return_type) {
  budget::String out = "(";
  for (const budget::String& p : params) {
    out += p;
  }
  out += ')';
  out += return_type;
  return out;
}

budget::String make_proto(std::initializer_list<std::string_view> params, std::string_view return_type) {
  budget::String out = "(";
  for (std::string_view p : params) {
    out += p;
  }
  out += ')';
  out += return_type;
  return out;
}

budget::String shorty_of(std::string_view proto) {
  auto shorty_char = [](std::string_view type) {
    return (type.front() == 'L' || type.front() == '[') ? 'L' : type.front();
  };
  auto parts = parse_proto(proto);
  if (!parts) {
    return {};
  }
  budget::String out(1, shorty_char(parts->return_type));
  for (std::string_view p : parts->params) {
    out += shorty_char(p);
  }
  return out;
}

uint32_t parameter_words(std::string_view proto) {
  auto parts = parse_proto(proto);
  if (!parts) {
    return 0;
  }
  uint32_t words = 0;
  for (std::string_view p : parts->params) {
    words += (p == "J" || p == "D") ? 2 : 1;
  }
  return words;
}

budget::String descriptor_of_class(std::string_view binary_name) {
  budget::String out = "L";
  for (char c : binary_name) {
    out += c == '.' ? '/' : c;
  }
  out += ';';
  return out;
}

budget::String java_name_of(std::string_view descriptor) {
  if (descriptor.size() == 1) {
    switch (descriptor[0]) {
      case 'V':
        return "void";
      case 'Z':
        return "boolean";
      case 'B':
        return "byte";
      case 'S':
        return "short";
      case 'C':
        return "char";
      case 'I':
        return "int";
      case 'J':
        return "long";
      case 'F':
        return "float";
      case 'D':
        return "double";
      default:
        break;
    }
  }
  std::string_view body = descriptor;
  if (body.size() >= 2 && body.front() == 'L' && body.back() == ';') {
    body = body.substr(1, body.size() - 2);
  }
  budget::String out;
  out.reserve(body.size());
  for (char c : body) {
    out += c == '/' ? '.' : c;
  }
  return out;
}

}  // namespace dexsplit::raw
