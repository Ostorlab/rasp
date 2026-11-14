// Checks of the rules a DEX writer can break, made with the raw parser only.

#pragma once

#include <algorithm>
#include <cstdint>
#include <format>
#include <map>
#include <set>
#include <span>
#include <string>
#include <tuple>
#include <vector>

#include "raw/constants.hpp"
#include "raw/mutf8.hpp"
#include "raw/parser.hpp"
#include "raw/types.hpp"

namespace dexsplit::support {

inline std::vector<std::string> check_dex(std::span<const uint8_t> b)
{
    using namespace raw;
    std::vector<std::string> problems;
    auto problem = [&](std::string s) { problems.push_back(std::move(s)); };

    auto dex = parser::parse_buffer(b, {.decode_strings = false});
    if (!dex) {
        problem("does not parse: " + dex.error().message);
        return problems;
    }
    const Header &h = dex->header();

    if (h.file_size != b.size())
        problem("file_size does not match the file");
    if (h.header_size != 0x70)
        problem("header_size is not 0x70");
    if (h.endian_tag != ENDIAN_CONSTANT)
        problem("bad endian tag");
    if (h.link_size != 0 || h.link_off != 0)
        problem("link section present");
    if (*parser::compute_checksum(b) != h.checksum)
        problem("bad checksum");
    auto sig = *parser::compute_signature(b);
    if (!std::equal(sig.begin(), sig.end(), h.signature))
        problem("bad signature");
    if (h.data_size % 4 != 0 || uint64_t{h.data_off} + h.data_size != b.size())
        problem("data section does not end the file or is not a multiple of 4");
    auto pair_ok = [&](uint32_t size, uint32_t off, const char *what) {
        if ((size == 0) != (off == 0))
            problem(std::format("{}: offset {} with size {}", what, off, size));
        if (off % 4 != 0)
            problem(std::format("{} is not 4-byte aligned", what));
    };
    pair_ok(h.string_ids_size, h.string_ids_off, "string_ids");
    pair_ok(h.type_ids_size, h.type_ids_off, "type_ids");
    pair_ok(h.proto_ids_size, h.proto_ids_off, "proto_ids");
    pair_ok(h.field_ids_size, h.field_ids_off, "field_ids");
    pair_ok(h.method_ids_size, h.method_ids_off, "method_ids");
    pair_ok(h.class_defs_size, h.class_defs_off, "class_defs");

    const MapList &map = dex->map_list();
    std::set<uint16_t> seen;
    for (std::size_t i = 0; i < map.items.size(); ++i) {
        const MapItem &m = map.items[i];
        if (i > 0 && map.items[i - 1].offset >= m.offset)
            problem("map list is not sorted by offset");
        if (!seen.insert(m.type).second)
            problem(std::format("map lists type 0x{:x} twice", m.type));
        bool byte_aligned = m.type == TYPE_CLASS_DATA_ITEM || m.type == TYPE_STRING_DATA_ITEM ||
                            m.type == TYPE_DEBUG_INFO_ITEM || m.type == TYPE_ANNOTATION_ITEM ||
                            m.type == TYPE_ENCODED_ARRAY_ITEM;
        if (!byte_aligned && m.offset % 4 != 0)
            problem(std::format("section 0x{:x} is not 4-byte aligned", m.type));
        if (m.size == 0)
            problem(std::format("section 0x{:x} is empty", m.type));
    }
    if (!seen.contains(TYPE_HEADER_ITEM) || !seen.contains(TYPE_MAP_LIST))
        problem("map list lacks the header or itself");

    std::vector<std::string> strings;
    for (uint32_t off : dex->string_ids()) {
        auto s = mutf8::decode_string_data(b, off);
        if (!s) {
            problem("bad string data: " + s.error().message);
            return problems;
        }
        if (!strings.empty() && mutf8::compare_utf16(strings.back(), *s) >= 0)
            problem("string_ids out of order: \"" + strings.back() + "\" then \"" + *s + "\"");
        strings.push_back(std::move(*s));
    }
    auto ids = dex->type_ids();
    for (std::size_t i = 1; i < ids.size(); ++i)
        if (ids[i - 1] >= ids[i])
            problem("type_ids out of order");

    auto params_of = [&](const ProtoIdItem &p) {
        std::vector<uint16_t> out;
        if (p.parameters_off != 0)
            out = parser::parse_type_list(b, p.parameters_off)->type_ids;
        return out;
    };
    auto protos = dex->proto_ids();
    for (std::size_t i = 1; i < protos.size(); ++i)
        if (std::make_tuple(protos[i - 1].return_type_idx, params_of(protos[i - 1])) >=
            std::make_tuple(protos[i].return_type_idx, params_of(protos[i])))
            problem("proto_ids out of order");
    auto fields = dex->field_ids();
    for (std::size_t i = 1; i < fields.size(); ++i)
        if (std::tie(fields[i - 1].class_idx, fields[i - 1].name_idx, fields[i - 1].type_idx) >=
            std::tie(fields[i].class_idx, fields[i].name_idx, fields[i].type_idx))
            problem("field_ids out of order");
    auto methods = dex->method_ids();
    for (std::size_t i = 1; i < methods.size(); ++i)
        if (std::tie(methods[i - 1].class_idx, methods[i - 1].name_idx, methods[i - 1].proto_idx) >=
            std::tie(methods[i].class_idx, methods[i].name_idx, methods[i].proto_idx))
            problem("method_ids out of order");

    std::map<uint32_t, std::size_t> class_pos;
    auto defs = dex->class_defs();
    for (std::size_t i = 0; i < defs.size(); ++i)
        if (!class_pos.emplace(defs[i].class_idx, i).second)
            problem("a class is defined twice");
    for (std::size_t i = 0; i < defs.size(); ++i) {
        const ClassDefItem &cd = defs[i];
        auto before = [&](uint32_t type) {
            auto it = class_pos.find(type);
            if (it != class_pos.end() && it->second > i)
                problem("a class is defined before its supertype");
        };
        if (cd.superclass_idx != NO_INDEX)
            before(cd.superclass_idx);
        if (cd.interfaces_off != 0) {
            auto interfaces = parser::parse_type_list(b, cd.interfaces_off);
            for (uint16_t t : interfaces->type_ids)
                before(t);
        }
        if (cd.class_data_off == 0)
            continue;
        auto data = parser::parse_class_data(b, cd.class_data_off);
        if (!data) {
            problem("bad class data");
            continue;
        }
        auto increasing = [&](const auto &list, auto index, const char *what) {
            for (std::size_t k = 1; k < list.size(); ++k)
                if (index(list[k - 1]) >= index(list[k]))
                    problem(std::format("{} out of order", what));
        };
        auto field_idx = [](const EncodedField &f) { return f.field_idx; };
        auto method_idx = [](const EncodedMethod &m) { return m.method_idx; };
        increasing(data->static_fields, field_idx, "static fields");
        increasing(data->instance_fields, field_idx, "instance fields");
        increasing(data->direct_methods, method_idx, "direct methods");
        increasing(data->virtual_methods, method_idx, "virtual methods");
        for (const auto &f : data->static_fields)
            if ((f.access_flags & 0x8) == 0)
                problem("an instance field in the static list");
        for (const auto *list : {&data->direct_methods, &data->virtual_methods}) {
            bool direct_list = list == &data->direct_methods;
            for (const EncodedMethod &m : *list) {
                std::string_view name = strings[methods[m.method_idx].name_idx];
                bool direct =
                    (m.access_flags & (0x8 | 0x2)) != 0 || name == "<init>" || name == "<clinit>";
                if (direct != direct_list)
                    problem(std::format("method {} is in the wrong list", name));
                if (m.code_off == 0)
                    continue;
                auto code = parser::parse_code_item(b, m.code_off);
                if (!code) {
                    problem("bad code item");
                    continue;
                }
                uint32_t end = 0;
                for (const TryItem &t : code->tries) {
                    if (t.start_addr < end || t.insn_count == 0 ||
                        uint64_t{t.start_addr} + t.insn_count > code->insns_size)
                        problem("try items overlap, are empty or run past the code");
                    end = t.start_addr + t.insn_count;
                }
            }
        }
        if (cd.annotations_off != 0) {
            auto dir = parser::parse_annotations_directory(b, cd.annotations_off);
            if (!dir) {
                problem("bad annotations directory");
                continue;
            }
            std::vector<uint32_t> sets;
            if (dir->class_annotations_off != 0)
                sets.push_back(dir->class_annotations_off);
            for (const auto &f : dir->field_annotations)
                sets.push_back(f.annotations_off);
            for (const auto &m : dir->method_annotations)
                sets.push_back(m.annotations_off);
            for (uint32_t off : sets) {
                auto set = parser::parse_annotation_set(b, off);
                if (!set)
                    continue;
                uint32_t last = 0;
                for (std::size_t k = 0; k < set->entries.size(); ++k) {
                    auto item = parser::parse_annotation_item(b, set->entries[k]);
                    if (!item)
                        continue;
                    if (k > 0 && item->annotation.type_idx <= last)
                        problem("annotation set out of order");
                    last = item->annotation.type_idx;
                }
            }
        }
    }
    return problems;
}

} // namespace dexsplit::support
