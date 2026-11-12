/** Python bindings for the trimmed dex splitter's native core (dexsplit._dex).
 *
 *  Exposes only what the Python splitter needs: an analysis context built from
 *  in-memory DEX bytes, the per-class links it reads (superclass, interfaces,
 *  and each method's calls, field accesses and type uses), and the editable DEX
 *  model used to regroup classes into new DEX files and to measure pool sizes.
 *
 *  Conventions at the boundary:
 *  - string_views are copied into owned Python str, so they never dangle;
 *  - a parse or write failure raises ValueError. */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "analysis/analysis_context.hpp"
#include "analysis/class.hpp"
#include "analysis/class_ref.hpp"
#include "analysis/method.hpp"
#include "common/ids.hpp"
#include "model/copy.hpp"
#include "model/model.hpp"
#include "raw/descriptors.hpp"

namespace py = pybind11;
namespace budget = dexsplit::budget;

namespace {

using dexsplit::AnalysisContext;
using dexsplit::Class;
using dexsplit::ClassRef;
using dexsplit::FieldAccess;
using dexsplit::FieldId;
using dexsplit::Method;
using dexsplit::MethodCall;
using dexsplit::MethodId;
using dexsplit::TypeUse;
using dexsplit::model::Dex;

/// Validate layout before constructing a span, including direct buffer callers.
std::span<const uint8_t> byte_buffer(const py::buffer& data) {
  auto info = data.request();
  if (info.ndim != 1 || info.itemsize != 1 || info.size < 0 || info.strides[0] != 1 ||
      (info.format != "B" && info.format != "b" && info.format != "c")) {
    throw py::value_error("DEX input must be a contiguous one-dimensional byte buffer");
  }
  auto size = static_cast<std::size_t>(info.size);
  if (size > budget::kDexBytes) {
    throw py::value_error("DEX exceeds 64 MiB compatibility limit");
  }
  return {static_cast<const uint8_t*>(info.ptr), size};
}

/// Python splitter shares this single request across reads, analysis, copies and writer retries.
struct Request {
  std::shared_ptr<budget::State> state = std::make_shared<budget::State>();
  std::unique_ptr<budget::Scope> scope;
  Request(std::size_t work, std::size_t storage) {
    if (work > budget::kWork || storage > budget::kAllocationBytes) {
      throw py::value_error("request limits exceed finite defaults");
    }
    if (budget::active != nullptr) {
      state = budget::active;
      state->max_work = std::min(state->max_work, work);
      state->max_storage = std::min(state->max_storage, storage);
    } else {
      state->max_work = work;
      state->max_storage = storage;
    }
  }
  void enter() {
    if (scope != nullptr) {
      throw py::value_error("request already entered");
    }
    scope = std::make_unique<budget::Scope>(state);
  }
  void leave() { scope.reset(); }
};

/** Raise the right Python exception for a model Error: FileNotFoundError when a
 *  file could not be opened, ValueError otherwise (malformed input, an
 *  unsupported feature, an invalid model, a pool overflow, a version too low). */
[[noreturn]] void raise_model_error(const dexsplit::model::Error& error) {
  if (error.kind == dexsplit::model::Error::Kind::TooLarge) {
    PyErr_SetString(PyExc_OverflowError, error.message.c_str());
    throw py::error_already_set();
  }
  if (error.kind == dexsplit::model::Error::Kind::Io) {
    PyErr_SetString(PyExc_FileNotFoundError, error.message.c_str());
    throw py::error_already_set();
  }
  throw py::value_error(error.message.c_str());
}

/** Register the analysis handles (context, class, method and the per-class links). */
void register_analysis(py::module_& m) {
  py::class_<MethodId>(m, "MethodId")
      .def_property_readonly(
          "class_descriptor", [](const MethodId& id) { return id.class_descriptor; },
          "The 'L...;' descriptor of the class that declares the method.");

  py::class_<FieldId>(m, "FieldId")
      .def_property_readonly(
          "class_descriptor", [](const FieldId& id) { return id.class_descriptor; },
          "The 'L...;' descriptor of the class that declares the field.");

  py::class_<ClassRef>(m, "ClassRef")
      .def_property_readonly(
          "descriptor", [](const ClassRef& ref) { return std::string(ref.descriptor()); },
          "The 'L...;' type descriptor this reference names.");

  py::class_<MethodCall>(m, "MethodCall")
      .def_property_readonly(
          "target", [](const MethodCall& call) { return call.target; }, "The declared callee of the call site.");

  py::class_<FieldAccess>(m, "FieldAccess")
      .def_property_readonly(
          "field", [](const FieldAccess& access) { return access.field; },
          "The field the instruction reads or writes.");

  py::class_<TypeUse>(m, "TypeUse")
      .def_property_readonly(
          "descriptor", [](const TypeUse& use) { return std::string(use.descriptor); },
          "The referenced type descriptor.");

  py::class_<Method>(m, "Method")
      .def_property_readonly("calls", &Method::calls, "The methods this body calls.")
      .def_property_readonly("field_accesses", &Method::field_accesses, "The fields this body reads or writes.")
      .def_property_readonly("type_uses", &Method::type_uses, "The types this body references.");

  py::class_<Class>(m, "Class")
      .def_property_readonly(
          "name", [](const Class& cls) { return std::string(cls.name()); },
          "The 'L...;' type descriptor that names this class.")
      .def_property_readonly("superclass", &Class::superclass,
                             "A ClassRef for the superclass, or None for java.lang.Object.")
      .def_property_readonly("interfaces", &Class::interfaces, "The interfaces this class implements.")
      .def_property_readonly("methods", &Class::methods, "The methods this class defines.");

  py::class_<AnalysisContext>(m, "AnalysisContext")
      .def_static(
          "from_dex_buffers",
          [](const py::sequence& dexes) {
            budget::Scope scope;
            if (dexes.size() > budget::kFiles) {
              throw py::value_error("DEX entry count limit exceeded");
            }
            budget::Vector<std::span<const uint8_t>> buffers;
            std::size_t total = 0;
            for (py::handle dex : dexes) {
              dexsplit::budget::visit();
              auto bytes = byte_buffer(py::reinterpret_borrow<py::buffer>(dex));
              if (bytes.size() > budget::kTotalBytes - total) {
                throw py::value_error("aggregate DEX input limit exceeded");
              }
              total += bytes.size();
              buffers.push_back(bytes);
            }
            auto result = AnalysisContext::from_dex_buffers(buffers);
            if (!result.has_value()) {
              throw py::value_error(result.error().c_str());
            }
            return std::move(*result);
          },
          py::arg("dexes"), "Parse a list of DEX byte strings (multidex order) into one context.")
      .def_static("from_models",
                  [](const py::sequence& models) {
                    if (models.size() > budget::kFiles) {
                      throw py::value_error("DEX file count limit exceeded");
                    }
                    std::shared_ptr<budget::State> request;
                    if (!models.empty()) {
                      request = py::cast<const Dex&>(models[0]).request;
                    }
                    budget::Scope scope(request);
                    budget::Vector<const Dex*> pointers;
                    for (py::handle item : models) {
                      const auto& model = py::cast<const Dex&>(item);
                      if (model.request != budget::active) {
                        throw py::value_error("read all analyzed models within one Request");
                      }
                      pointers.push_back(&model);
                    }
                    auto result = AnalysisContext::from_models(pointers);
                    if (!result) {
                      throw py::value_error(result.error().c_str());
                    }
                    return std::move(*result);
                  })
      .def_property_readonly("classes", &AnalysisContext::classes, "Every class across the loaded DEX files.");
}

/** Register the editable DEX model and its pool statistics. */
void register_model(py::module_& m) {
  py::class_<dexsplit::model::PoolStats>(m, "PoolStats")
      .def_readonly("strings", &dexsplit::model::PoolStats::strings)
      .def_readonly("types", &dexsplit::model::PoolStats::types)
      .def_readonly("protos", &dexsplit::model::PoolStats::protos)
      .def_readonly("fields", &dexsplit::model::PoolStats::fields)
      .def_readonly("methods", &dexsplit::model::PoolStats::methods)
      .def_readonly("method_handles", &dexsplit::model::PoolStats::method_handles)
      .def_readonly("call_sites", &dexsplit::model::PoolStats::call_sites);

  py::class_<Dex>(m, "Model",
                  "An editable in-memory DEX file: read DEX bytes into a model, copy whole "
                  "classes between models, and write DEX bytes again.")
      .def(py::init([](uint32_t version) {
             budget::Scope scope;
             Dex dex;
             dex.version = version;
             return dex;
           }),
           py::arg("version") = 35, "An empty model of the given DEX version.")
      .def_static(
          "read",
          [](const py::buffer& data) {
            budget::Scope scope;
            auto bytes = byte_buffer(data);
            auto result = dexsplit::model::read(bytes);
            if (!result) {
              raise_model_error(result.error());
            }
            return std::move(*result);
          },
          py::arg("data"), "Read DEX bytes into a model.")
      .def_property_readonly(
          "version", [](const Dex& dex) { return dex.version; }, "The DEX format version write() will use.")
      .def_property_readonly(
          "pool_stats",
          [](const Dex& dex) {
            budget::Scope scope(dex.request);
            return dexsplit::model::pool_stats(dex);
          },
          "The pool sizes the model would write (see PoolStats).")
      .def_property_readonly(
          "class_descriptors",
          [](const Dex& dex) {
            budget::Scope scope(dex.request);
            budget::Vector<budget::String> out;
            out.reserve(dex.classes.size());
            for (const auto& cls : dex.classes) {
              dexsplit::budget::visit();
              out.push_back(cls.type);
            }
            return out;
          },
          "Every class's descriptor, in model order.")
      .def(
          "copy_class",
          [](Dex& dst, const Dex& src, std::string_view descriptor) {
            budget::Scope scope(dexsplit::model::copy_request(dst, src));
            std::array<std::string_view, 1> names{descriptor};
            auto result = dexsplit::model::copy_classes(dst, src, names);
            if (!result) {
              raise_model_error(result.error());
            }
          },
          py::arg("src"), py::arg("descriptor"), "Copy the class from src into this model, leaving src unchanged.")
      .def("copy_classes",
           [](Dex& dst, const Dex& src, const py::sequence& descriptors) {
             budget::Scope scope(dexsplit::model::copy_request(dst, src));
             if (descriptors.size() > budget::kClasses - std::min(dst.classes.size(), budget::kClasses)) {
               throw py::value_error("DEX unique class count exceeds 100000");
             }
             budget::Vector<std::string_view> names;
             names.reserve(descriptors.size());
             for (py::handle item : descriptors) {
               names.push_back(py::cast<std::string_view>(item));
             }
             auto result = dexsplit::model::copy_classes(dst, src, names);
             if (!result) {
               raise_model_error(result.error());
             }
           })
      .def(
          "write",
          [](const Dex& dex) {
            budget::Scope scope(dex.request);
            auto result = dexsplit::model::write(dex);
            if (!result) {
              raise_model_error(result.error());
            }
            budget::active->charge(result->size() / 64 + 1, result->size());
            return py::bytes(reinterpret_cast<const char*>(result->data()), result->size());
          },
          "The model as DEX bytes.  Raises ValueError if a pool overflows or the model is "
          "invalid.");
}

}  // namespace

PYBIND11_MODULE(_dex, m) {
  m.doc() = "Native core of the dex splitter: DEX analysis and the editable DEX model.";
  m.def(
      "charge",
      [](std::size_t work, std::size_t storage) {
        if (budget::active != nullptr) {
          budget::active->charge(work, storage);
        }
      },
      py::arg("work") = 0, py::arg("storage") = 0);
  py::register_exception<budget::OutputLimit>(m, "OutputLimit", PyExc_ValueError);
  py::register_exception<budget::Exhausted>(m, "BudgetError", PyExc_ValueError);
  py::class_<Request>(m, "Request")
      .def(py::init<std::size_t, std::size_t>(), py::arg("work") = budget::kWork,
           py::arg("storage") = budget::kAllocationBytes)
      .def(
          "__enter__",
          [](Request& request) -> Request& {
            request.enter();
            return request;
          },
          py::return_value_policy::reference_internal)
      .def("__exit__",
           [](Request& request, const py::object&, const py::object&, const py::object&) { request.leave(); })
      .def(
          "charge",
          [](Request& request, std::size_t work, std::size_t storage) { request.state->charge(work, storage); },
          py::arg("work") = 0, py::arg("storage") = 0)
      .def_property_readonly("work", [](const Request& request) { return request.state->work; })
      .def_property_readonly("storage", [](const Request& request) { return request.state->storage; })
      .def_property_readonly("backing", [](const Request& request) { return request.state->backing; });
  m.def("valid_class_name", [](std::string_view name) {
    budget::Scope scope;
    if (name.empty() || name.find_first_of("/,\r\n\0", 0, 5) != std::string_view::npos) {
      return false;
    }
    budget::String descriptor = "L";
    descriptor.append(name);
    std::replace(descriptor.begin(), descriptor.end(), '.', '/');
    descriptor += ';';
    return dexsplit::raw::is_valid_class_descriptor(descriptor, 40);
  });
  register_analysis(m);
  register_model(m);
}
