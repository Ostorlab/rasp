#include <algorithm>
#include <format>
#include <fstream>
#include <unordered_map>

#include "model/code_encoder.hpp"
#include "model/io.hpp"
#include "model/pools.hpp"
#include "model/rules.hpp"
#include "model/value_encoder.hpp"
#include "raw/byte_writer.hpp"
#include "raw/constants.hpp"
#include "raw/digest.hpp"
#include "raw/parser.hpp"

namespace dexsplit::model {

namespace {

using namespace detail;

struct VectorHash
{
    template <class T> std::size_t operator()(const std::vector<T> &v) const noexcept
    {
        std::size_t h = v.size();
        for (const T &x : v)
            h = h * 1000003u ^ std::hash<T>{}(x);
        return h;
    }
};

class Writer
{
  public:
    Writer(const Dex &dex, const WriteOptions &options) : dex_(dex), options_(options) {}

    std::vector<uint8_t> run();

  private:
    void order_classes();
    uint32_t type_list(const std::vector<uint16_t> &types);

    const Dex &dex_;
    const WriteOptions &options_;
    std::vector<const ClassDef *> classes_;
    Pools pools_;
    CallSites sites_;
    raw::ByteWriter out_;

    std::unordered_map<std::vector<uint16_t>, uint32_t, VectorHash> type_lists_;
    std::vector<std::vector<uint16_t>> type_list_order_;
};

// Supertypes defined in the file come before their subtypes (ART rejects
// the file otherwise); the rest keeps the model's order.  A post-order walk
// with an explicit stack: a hierarchy can be thousands of classes deep.
void Writer::order_classes()
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
    struct Frame
    {
        const ClassDef *cls;
        std::vector<const ClassDef *> next;
        std::size_t i = 0;
    };
    std::unordered_set<const ClassDef *> seen;
    for (const ClassDef &root : dex_.classes) {
        if (!seen.insert(&root).second)
            continue;
        std::vector<Frame> stack;
        stack.push_back({&root, supers(&root)});
        while (!stack.empty()) {
            Frame &top = stack.back();
            if (top.i == top.next.size()) {
                classes_.push_back(top.cls);
                stack.pop_back();
                continue;
            }
            const ClassDef *next = top.next[top.i++];
            if (seen.insert(next).second)
                stack.push_back({next, supers(next)});
        }
    }
}

std::vector<uint8_t> Writer::run()
{
    order_classes();
    for (const ClassDef *c : classes_)
        pools_.add_class(*c, options_.debug_info);
    pools_.finish();
    const ValueEncoder values(pools_);

    // Encode every method's code first: it numbers the call sites.
    struct MethodOut
    {
        const MethodDef *method;
        uint32_t index;
        CodeOut code;
        bool has_code;
    };
    struct ClassOut
    {
        const ClassDef *cls;
        std::vector<std::pair<const FieldDef *, uint32_t>> static_fields, instance_fields;
        std::vector<MethodOut> direct, virtual_;
    };
    std::vector<ClassOut> class_out;
    class_out.reserve(classes_.size());
    for (const ClassDef *c : classes_) {
        ClassOut co{c, {}, {}, {}, {}};
        for (const FieldDef &f : c->fields) {
            uint32_t idx = pools_.field(FieldId{c->type, f.name, f.type});
            (has(f.access, AccessFlags::Static) ? co.static_fields : co.instance_fields)
                .emplace_back(&f, idx);
        }
        for (const MethodDef &m : c->methods) {
            uint32_t idx = pools_.method(MethodId{c->type, m.name, m.proto});
            (detail::is_direct(m) ? co.direct : co.virtual_)
                .push_back(MethodOut{&m, idx, {}, m.code.has_value()});
        }
        auto by_index = [](const auto &a, const auto &b) { return a.second < b.second; };
        std::sort(co.static_fields.begin(), co.static_fields.end(), by_index);
        std::sort(co.instance_fields.begin(), co.instance_fields.end(), by_index);
        auto by_method = [](const MethodOut &a, const MethodOut &b) { return a.index < b.index; };
        std::sort(co.direct.begin(), co.direct.end(), by_method);
        std::sort(co.virtual_.begin(), co.virtual_.end(), by_method);
        for (auto *list : {&co.direct, &co.virtual_})
            for (MethodOut &mo : *list)
                if (mo.has_code) {
                    CodeEncoder encoder(
                        pools_, sites_,
                        std::format("{}->{}{}", c->type, mo.method->name, mo.method->proto));
                    mo.code = encoder.encode(*mo.method, *mo.method->code, options_.debug_info);
                }
        class_out.push_back(std::move(co));
    }

    if (sites_.list().size() > 65536)
        fail(Error::Kind::TooLarge,
             std::format("{} call sites; a DEX file holds at most 65536", sites_.list().size()));

    // ----- id sections: sizes are known, contents are filled at the end -----
    const auto &strings = pools_.strings();
    const auto &types = pools_.types();
    const auto &protos = pools_.protos();
    const auto &fields = pools_.fields();
    const auto &methods = pools_.methods();
    const auto &handles = pools_.method_handles();
    const auto &sites = sites_.list();

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
    out_.append(std::vector<uint8_t>(data_off, 0));

    struct MapEntry
    {
        uint16_t type;
        uint32_t count;
        uint32_t offset;
    };
    std::vector<MapEntry> map{{raw::TYPE_HEADER_ITEM, 1, 0}};
    auto add_map = [&](uint16_t type, std::size_t count, uint32_t offset) {
        if (count != 0)
            map.push_back({type, static_cast<uint32_t>(count), offset});
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
    std::unordered_map<const MethodDef *, uint32_t> code_offsets;
    std::vector<std::pair<std::size_t, const CodeOut *>> debug_patches;
    {
        uint32_t first = 0;
        std::size_t count = 0;
        for (const ClassOut &co : class_out)
            for (const auto *list : {&co.direct, &co.virtual_})
                for (const MethodOut &mo : *list) {
                    if (!mo.has_code)
                        continue;
                    out_.align(4);
                    uint32_t off = static_cast<uint32_t>(out_.size());
                    if (count++ == 0)
                        first = off;
                    code_offsets[mo.method] = off;
                    const CodeOut &c = mo.code;
                    out_.u16(c.registers);
                    out_.u16(c.ins);
                    out_.u16(c.outs);
                    out_.u16(static_cast<uint16_t>(c.tries.size()));
                    debug_patches.emplace_back(out_.size(), &c);
                    out_.u32(0); // debug_info_off, patched below
                    out_.u32(static_cast<uint32_t>(c.insns.size()));
                    for (uint16_t u : c.insns)
                        out_.u16(u);
                    if (!c.tries.empty()) {
                        if (c.insns.size() % 2 != 0)
                            out_.u16(0);
                        for (const CodeOut::Try &t : c.tries) {
                            out_.u32(t.start);
                            out_.u16(t.count);
                            out_.u16(t.handler_off);
                        }
                        out_.append(c.handlers);
                    }
                }
        add_map(raw::TYPE_CODE_ITEM, count, first);
    }

    // ----- debug info: methods with identical debug info share one item -----
    {
        std::unordered_map<std::vector<uint8_t>, uint32_t, VectorHash> written;
        uint32_t first = 0;
        for (const auto &[patch_at, code] : debug_patches) {
            if (code->debug.empty())
                continue;
            auto [it, inserted] = written.emplace(code->debug, static_cast<uint32_t>(out_.size()));
            if (inserted) {
                if (written.size() == 1)
                    first = it->second;
                out_.append(code->debug);
            }
            out_.put_u32(patch_at, it->second);
        }
        add_map(raw::TYPE_DEBUG_INFO_ITEM, written.size(), first);
    }

    // ----- type lists: prototype parameters and interfaces -----
    std::vector<uint32_t> proto_params_off(protos.size(), 0);
    std::vector<uint32_t> interfaces_off(class_out.size(), 0);
    {
        for (std::size_t i = 0; i < protos.size(); ++i)
            if (!protos[i].params.empty())
                type_list(protos[i].params);
        std::vector<std::vector<uint16_t>> interface_lists(class_out.size());
        for (std::size_t i = 0; i < class_out.size(); ++i)
            for (const std::string &iface : class_out[i].cls->interfaces)
                interface_lists[i].push_back(static_cast<uint16_t>(pools_.type(iface)));
        for (const auto &list : interface_lists)
            if (!list.empty())
                type_list(list);
        uint32_t first = 0;
        for (std::size_t k = 0; k < type_list_order_.size(); ++k) {
            out_.align(4);
            uint32_t off = static_cast<uint32_t>(out_.size());
            if (k == 0)
                first = off;
            type_lists_[type_list_order_[k]] = off;
            out_.u32(static_cast<uint32_t>(type_list_order_[k].size()));
            for (uint16_t t : type_list_order_[k])
                out_.u16(t);
        }
        add_map(raw::TYPE_TYPE_LIST, type_list_order_.size(), first);
        for (std::size_t i = 0; i < protos.size(); ++i)
            if (!protos[i].params.empty())
                proto_params_off[i] = type_lists_.at(protos[i].params);
        for (std::size_t i = 0; i < class_out.size(); ++i)
            if (!interface_lists[i].empty())
                interfaces_off[i] = type_lists_.at(interface_lists[i]);
    }

    // ----- string data -----
    std::vector<uint32_t> string_data_off(strings.size());
    {
        std::vector<uint8_t> mutf8;
        for (std::size_t i = 0; i < strings.size(); ++i) {
            string_data_off[i] = static_cast<uint32_t>(out_.size());
            out_.uleb128(raw::mutf8::utf16_length(strings[i]));
            mutf8.clear();
            raw::mutf8::append_mutf8(strings[i], mutf8);
            out_.append(mutf8);
            out_.u8(0);
        }
        add_map(raw::TYPE_STRING_DATA_ITEM, strings.size(),
                strings.empty() ? 0 : string_data_off[0]);
    }

    // ----- annotation items -----
    // Each distinct annotation is written once; annotation sets refer to them.
    struct AnnotationRef
    {
        uint32_t type;
        uint32_t offset;
    };
    std::vector<std::vector<uint8_t>> annotation_bytes;
    std::unordered_map<std::vector<uint8_t>, uint32_t, VectorHash> annotation_index;
    auto annotation_id = [&](const AnnotationItem &a) {
        raw::ByteWriter w;
        w.u8(static_cast<uint8_t>(a.visibility));
        values.annotation(w, a.annotation);
        auto [it, inserted] =
            annotation_index.emplace(w.bytes(), static_cast<uint32_t>(annotation_bytes.size()));
        if (inserted)
            annotation_bytes.push_back(w.take());
        return it->second;
    };
    // Every annotation set of the file, in order: class, fields, methods, parameters.
    struct ClassAnnotations
    {
        std::vector<uint32_t> class_set;
        std::vector<std::pair<uint32_t, std::vector<uint32_t>>> fields;  // field idx, ids
        std::vector<std::pair<uint32_t, std::vector<uint32_t>>> methods; // method idx, ids
        std::vector<std::pair<uint32_t, std::vector<std::vector<uint32_t>>>> parameters;
    };
    std::vector<ClassAnnotations> class_annotations(class_out.size());
    std::vector<uint32_t> annotation_type; // per annotation id
    // Annotations are numbered in the file's own order — members by index,
    // each set by type — not the model's, so the layout does not depend on
    // how the model happens to order them.
    for (std::size_t i = 0; i < class_out.size(); ++i) {
        const ClassOut &co = class_out[i];
        ClassAnnotations &ca = class_annotations[i];
        auto ids = [&](const std::vector<AnnotationItem> &set) {
            std::vector<std::pair<uint32_t, const AnnotationItem *>> by_type;
            for (const AnnotationItem &a : set)
                by_type.emplace_back(pools_.type(a.annotation.type), &a);
            std::sort(by_type.begin(), by_type.end(),
                      [](const auto &x, const auto &y) { return x.first < y.first; });
            std::vector<uint32_t> out;
            for (const auto &[type, a] : by_type) {
                uint32_t id = annotation_id(*a);
                if (id >= annotation_type.size())
                    annotation_type.push_back(type);
                out.push_back(id);
            }
            return out;
        };
        ca.class_set = ids(co.cls->annotations);
        std::vector<std::pair<const FieldDef *, uint32_t>> fields = co.static_fields;
        fields.insert(fields.end(), co.instance_fields.begin(), co.instance_fields.end());
        std::sort(fields.begin(), fields.end(),
                  [](const auto &x, const auto &y) { return x.second < y.second; });
        for (const auto &[f, idx] : fields)
            if (!f->annotations.empty())
                ca.fields.emplace_back(idx, ids(f->annotations));
        std::vector<const MethodOut *> methods;
        for (const auto *list : {&co.direct, &co.virtual_})
            for (const MethodOut &mo : *list)
                methods.push_back(&mo);
        std::sort(methods.begin(), methods.end(),
                  [](const MethodOut *x, const MethodOut *y) { return x->index < y->index; });
        for (const MethodOut *mo : methods) {
            const MethodDef &m = *mo->method;
            if (!m.annotations.empty())
                ca.methods.emplace_back(mo->index, ids(m.annotations));
            if (!m.parameter_annotations.empty()) {
                std::vector<std::vector<uint32_t>> sets;
                for (const auto &set : m.parameter_annotations)
                    sets.push_back(ids(set));
                ca.parameters.emplace_back(mo->index, std::move(sets));
            }
        }
    }
    std::vector<uint32_t> annotation_off(annotation_bytes.size());
    for (std::size_t k = 0; k < annotation_bytes.size(); ++k) {
        annotation_off[k] = static_cast<uint32_t>(out_.size());
        out_.append(annotation_bytes[k]);
    }
    add_map(raw::TYPE_ANNOTATION_ITEM, annotation_bytes.size(),
            annotation_bytes.empty() ? 0 : annotation_off[0]);

    // ----- class data -----
    std::vector<uint32_t> class_data_off(class_out.size(), 0);
    {
        uint32_t first = 0;
        std::size_t count = 0;
        for (std::size_t i = 0; i < class_out.size(); ++i) {
            const ClassOut &co = class_out[i];
            if (co.static_fields.empty() && co.instance_fields.empty() && co.direct.empty() &&
                co.virtual_.empty())
                continue;
            uint32_t off = static_cast<uint32_t>(out_.size());
            if (count++ == 0)
                first = off;
            class_data_off[i] = off;
            out_.uleb128(static_cast<uint32_t>(co.static_fields.size()));
            out_.uleb128(static_cast<uint32_t>(co.instance_fields.size()));
            out_.uleb128(static_cast<uint32_t>(co.direct.size()));
            out_.uleb128(static_cast<uint32_t>(co.virtual_.size()));
            for (const auto *list : {&co.static_fields, &co.instance_fields}) {
                uint32_t prev = 0;
                for (const auto &[f, idx] : *list) {
                    out_.uleb128(idx - prev);
                    out_.uleb128(static_cast<uint32_t>(f->access));
                    prev = idx;
                }
            }
            for (const auto *list : {&co.direct, &co.virtual_}) {
                uint32_t prev = 0;
                for (const MethodOut &mo : *list) {
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
    std::vector<uint32_t> static_values_off(class_out.size(), 0);
    std::vector<uint32_t> call_site_off(sites.size(), 0);
    {
        std::unordered_map<std::vector<uint8_t>, uint32_t, VectorHash> arrays;
        uint32_t first = 0;
        std::size_t count = 0;
        auto emit = [&](std::vector<uint8_t> bytes, bool share) {
            if (share) {
                auto it = arrays.find(bytes);
                if (it != arrays.end())
                    return it->second;
            }
            uint32_t off = static_cast<uint32_t>(out_.size());
            if (count++ == 0)
                first = off;
            out_.append(bytes);
            if (share)
                arrays.emplace(std::move(bytes), off);
            return off;
        };
        for (std::size_t i = 0; i < class_out.size(); ++i) {
            const auto &statics = class_out[i].static_fields;
            std::size_t last = statics.size();
            while (last > 0 && !statics[last - 1].first->initial_value)
                --last;
            if (last == 0)
                continue;
            std::vector<Value> list;
            for (std::size_t k = 0; k < last; ++k) {
                const FieldDef &f = *statics[k].first;
                list.push_back(f.initial_value ? *f.initial_value : default_value(f.type));
            }
            raw::ByteWriter w;
            values.array(w, list);
            static_values_off[i] = emit(w.take(), true);
        }
        // Each call site gets its own item: call_site_ids must be in item order.
        for (std::size_t k = 0; k < sites.size(); ++k) {
            const CallSite &cs = *sites[k];
            std::vector<Value> list;
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
    std::vector<std::vector<uint32_t>> set_order;
    std::unordered_map<std::vector<uint32_t>, uint32_t, VectorHash> set_ids;
    auto set_id = [&](std::vector<uint32_t> ids) {
        // Entries in increasing order of the annotation's type index.
        std::sort(ids.begin(), ids.end(),
                  [&](uint32_t a, uint32_t b) { return annotation_type[a] < annotation_type[b]; });
        auto [it, inserted] = set_ids.emplace(ids, static_cast<uint32_t>(set_order.size()));
        if (inserted)
            set_order.push_back(std::move(ids));
        return it->second;
    };
    struct DirectoryIds
    {
        std::optional<uint32_t> class_set;
        std::vector<std::pair<uint32_t, uint32_t>> fields, methods; // member idx, set id
        std::vector<std::pair<uint32_t, std::vector<std::optional<uint32_t>>>> parameters;
    };
    std::vector<DirectoryIds> directory_ids(class_out.size());
    for (std::size_t i = 0; i < class_out.size(); ++i) {
        const ClassAnnotations &ca = class_annotations[i];
        DirectoryIds &d = directory_ids[i];
        if (!ca.class_set.empty())
            d.class_set = set_id(ca.class_set);
        for (const auto &[idx, ids] : ca.fields)
            d.fields.emplace_back(idx, set_id(ids));
        for (const auto &[idx, ids] : ca.methods)
            d.methods.emplace_back(idx, set_id(ids));
        for (const auto &[idx, sets] : ca.parameters) {
            std::vector<std::optional<uint32_t>> refs;
            for (const auto &ids : sets)
                refs.push_back(ids.empty() ? std::nullopt : std::optional(set_id(ids)));
            d.parameters.emplace_back(idx, std::move(refs));
        }
    }
    std::vector<uint32_t> set_off(set_order.size());
    {
        uint32_t first = 0;
        for (std::size_t k = 0; k < set_order.size(); ++k) {
            out_.align(4);
            set_off[k] = static_cast<uint32_t>(out_.size());
            if (k == 0)
                first = set_off[k];
            out_.u32(static_cast<uint32_t>(set_order[k].size()));
            for (uint32_t id : set_order[k])
                out_.u32(annotation_off[id]);
        }
        add_map(raw::TYPE_ANNOTATION_SET_ITEM, set_order.size(), first);
    }
    // Ref lists: one per method with parameter annotations.
    std::vector<std::vector<uint32_t>> ref_list_offsets(class_out.size());
    {
        uint32_t first = 0;
        std::size_t count = 0;
        for (std::size_t i = 0; i < class_out.size(); ++i)
            for (const auto &[idx, refs] : directory_ids[i].parameters) {
                out_.align(4);
                uint32_t off = static_cast<uint32_t>(out_.size());
                if (count++ == 0)
                    first = off;
                ref_list_offsets[i].push_back(off);
                out_.u32(static_cast<uint32_t>(refs.size()));
                for (const auto &ref : refs)
                    out_.u32(ref ? set_off[*ref] : 0);
            }
        add_map(raw::TYPE_ANNOTATION_SET_REF_LIST, count, first);
    }

    // ----- annotations directories -----
    std::vector<uint32_t> annotations_off(class_out.size(), 0);
    {
        std::unordered_map<std::vector<uint8_t>, uint32_t, VectorHash> dirs;
        uint32_t first = 0;
        std::size_t count = 0;
        for (std::size_t i = 0; i < class_out.size(); ++i) {
            const DirectoryIds &d = directory_ids[i];
            if (!d.class_set && d.fields.empty() && d.methods.empty() && d.parameters.empty())
                continue;
            raw::ByteWriter w;
            w.u32(d.class_set ? set_off[*d.class_set] : 0);
            w.u32(static_cast<uint32_t>(d.fields.size()));
            w.u32(static_cast<uint32_t>(d.methods.size()));
            w.u32(static_cast<uint32_t>(d.parameters.size()));
            for (const auto &[idx, set] : d.fields) {
                w.u32(idx);
                w.u32(set_off[set]);
            }
            for (const auto &[idx, set] : d.methods) {
                w.u32(idx);
                w.u32(set_off[set]);
            }
            for (std::size_t k = 0; k < d.parameters.size(); ++k) {
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
            if (count++ == 0)
                first = off;
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
    std::sort(map.begin(), map.end(),
              [](const MapEntry &a, const MapEntry &b) { return a.offset < b.offset; });
    out_.u32(static_cast<uint32_t>(map.size()));
    for (const MapEntry &e : map) {
        out_.u16(e.type);
        out_.u16(0);
        out_.u32(e.count);
        out_.u32(e.offset);
    }
    const uint32_t file_size = static_cast<uint32_t>(out_.size());

    // ----- id sections -----
    for (std::size_t i = 0; i < strings.size(); ++i)
        out_.put_u32(string_ids_off + 4 * i, string_data_off[i]);
    for (std::size_t i = 0; i < types.size(); ++i)
        out_.put_u32(type_ids_off + 4 * i, pools_.string(types[i]));
    for (std::size_t i = 0; i < protos.size(); ++i) {
        std::size_t at_proto = proto_ids_off + 12 * i;
        out_.put_u32(at_proto, protos[i].shorty);
        out_.put_u32(at_proto + 4, protos[i].return_type);
        out_.put_u32(at_proto + 8, proto_params_off[i]);
    }
    auto put_u16_pair = [&](std::size_t at_item, uint32_t lo, uint32_t hi) {
        out_.put_u32(at_item, (lo & 0xFFFF) | (hi << 16));
    };
    for (std::size_t i = 0; i < fields.size(); ++i) {
        std::size_t at_field = field_ids_off + 8 * i;
        put_u16_pair(at_field, pools_.type(fields[i].class_descriptor),
                     pools_.type(fields[i].type));
        out_.put_u32(at_field + 4, pools_.string(fields[i].name));
    }
    for (std::size_t i = 0; i < methods.size(); ++i) {
        std::size_t at_method = method_ids_off + 8 * i;
        put_u16_pair(at_method, pools_.type(methods[i].class_descriptor),
                     pools_.proto(methods[i].proto));
        out_.put_u32(at_method + 4, pools_.string(methods[i].name));
    }
    for (std::size_t i = 0; i < class_out.size(); ++i) {
        const ClassDef &c = *class_out[i].cls;
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
    for (std::size_t i = 0; i < sites.size(); ++i)
        out_.put_u32(call_site_ids_off + 4 * i, call_site_off[i]);
    for (std::size_t i = 0; i < handles.size(); ++i) {
        const MethodHandle &h = handles[i];
        uint32_t member = std::visit(
            [&](const auto &m) -> uint32_t {
                if constexpr (std::is_same_v<std::decay_t<decltype(m)>, FieldId>)
                    return pools_.field(m);
                else
                    return pools_.method(m);
            },
            h.member);
        std::size_t at_handle = method_handles_off + 8 * i;
        put_u16_pair(at_handle, static_cast<uint32_t>(h.kind), 0);
        put_u16_pair(at_handle + 4, member, 0);
    }

    // ----- header -----
    std::vector<uint8_t> bytes = out_.take();
    raw::ByteWriter header;
    const char magic[8] = {'d',
                           'e',
                           'x',
                           '\n',
                           static_cast<char>('0' + dex_.version / 100 % 10),
                           static_cast<char>('0' + dex_.version / 10 % 10),
                           static_cast<char>('0' + dex_.version % 10),
                           0};
    for (char ch : magic)
        header.u8(static_cast<uint8_t>(ch));
    header.u32(0);                              // checksum
    header.append(std::vector<uint8_t>(20, 0)); // signature
    header.u32(file_size);
    header.u32(header_size);
    header.u32(raw::ENDIAN_CONSTANT);
    header.u32(0); // link_size
    header.u32(0); // link_off
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
    for (int i = 0; i < 4; ++i)
        bytes[8 + i] = static_cast<uint8_t>(checksum >> (8 * i));
    return bytes;
}

uint32_t Writer::type_list(const std::vector<uint16_t> &types)
{
    auto [it, inserted] =
        type_lists_.emplace(types, static_cast<uint32_t>(type_list_order_.size()));
    if (inserted)
        type_list_order_.push_back(types);
    return it->second;
}

} // namespace

std::expected<std::vector<uint8_t>, Error> write(const Dex &dex, const WriteOptions &options)
{
    // A feature of a later version is reported as such, before the problems
    // it causes under the older rules (e.g. a space in a name).
    detail::Checked checked = detail::check(dex);
    const bool known_version = dex.version >= 35 && dex.version <= 40 && dex.version != 36;
    if (known_version && checked.needed_version > dex.version)
        return std::unexpected(
            Error{Error::Kind::VersionTooLow,
                  std::format("the model needs DEX {:03} ({}), but its version is {:03}",
                              checked.needed_version, checked.needed_reason, dex.version),
                  {}});
    std::vector<Problem> &problems = checked.problems;
    if (!problems.empty()) {
        std::string message =
            std::format("the model is not valid: {}{}{}", problems[0].where,
                        problems[0].where.empty() ? "" : ": ", problems[0].message);
        if (problems.size() > 1)
            message += std::format(" (and {} more)", problems.size() - 1);
        return std::unexpected(
            Error{Error::Kind::Invalid, std::move(message), std::move(problems)});
    }
    try {
        return Writer(dex, options).run();
    }
    catch (WriteFailure &failure) {
        return std::unexpected(std::move(failure.error));
    }
}

std::expected<void, Error> write_file(const Dex &dex, const std::string &path,
                                      const WriteOptions &options)
{
    auto bytes = write(dex, options);
    if (!bytes)
        return std::unexpected(std::move(bytes.error()));
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
        return std::unexpected(Error{Error::Kind::Io, std::format("cannot create {}", path), {}});
    out.write(reinterpret_cast<const char *>(bytes->data()),
              static_cast<std::streamsize>(bytes->size()));
    out.flush();
    if (!out)
        return std::unexpected(Error{Error::Kind::Io, std::format("cannot write {}", path), {}});
    return {};
}

PoolStats pool_stats(const Dex &dex)
{
    Pools pools;
    CallSites sites;
    PoolStats stats;
    for (const ClassDef &c : dex.classes) {
        pools.add_class(c, true);
        for (const MethodDef &m : c.methods)
            if (m.code)
                for (const Item &item : m.code->items)
                    if (const Insn *insn = std::get_if<Insn>(&item))
                        if (const InvokeCustom *ic = std::get_if<InvokeCustom>(insn))
                            sites.id(ic->call_site.get());
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

} // namespace dexsplit::model
