/** Python bindings for the trimmed dex splitter's native core (dexsplit._dex).
 *
 *  Exposes only what the Python splitter needs: the editable DEX model used to
 *  regroup classes into new DEX files and to measure pool sizes.
 *
 *  A parse or write failure raises ValueError; a pool overflow raises its
 *  subclass PoolOverflowError and a version that is too low VersionTooLowError. */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "model/model.hpp"

namespace py = pybind11;

namespace {

using dexsplit::model::Dex;

/** A model that has more entries in a pool than a DEX file can index. */
struct PoolOverflow : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

/** A model that uses a feature of a later DEX version than its own. */
struct VersionTooLow : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

/** Raise the right Python exception for a model Error: FileNotFoundError when a
 *  file could not be opened, PoolOverflowError for a pool overflow,
 *  VersionTooLowError for a version too low, ValueError otherwise (malformed
 *  input, an unsupported feature, an invalid model). */
[[noreturn]] void raise_model_error(const dexsplit::model::Error &error)
{
    using Kind = dexsplit::model::Error::Kind;
    if (error.kind == Kind::Io) {
        PyErr_SetString(PyExc_FileNotFoundError, error.message.c_str());
        throw py::error_already_set();
    }
    if (error.kind == Kind::TooLarge)
        throw PoolOverflow(error.message);
    if (error.kind == Kind::VersionTooLow)
        throw VersionTooLow(error.message);
    throw py::value_error(error.message);
}

/** Register the editable DEX model and its pool statistics. */
void register_model(py::module_ &m)
{
    py::register_exception<PoolOverflow>(m, "PoolOverflowError", PyExc_ValueError);
    py::register_exception<VersionTooLow>(m, "VersionTooLowError", PyExc_ValueError);

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
                 Dex dex;
                 dex.version = version;
                 return dex;
             }),
             py::arg("version") = 35, "An empty model of the given DEX version.")
        .def_static(
            "read",
            [](py::buffer data) {
                py::buffer_info info = data.request();
                auto bytes = std::span<const uint8_t>(
                    static_cast<const uint8_t *>(info.ptr),
                    static_cast<std::size_t>(info.size) * static_cast<std::size_t>(info.itemsize));
                auto result = dexsplit::model::read(bytes);
                if (!result)
                    raise_model_error(result.error());
                return std::move(*result);
            },
            py::arg("data"), "Read DEX bytes into a model.")
        .def_property_readonly(
            "version", [](const Dex &dex) { return dex.version; },
            "The DEX format version write() will use.")
        .def_property_readonly(
            "pool_stats", [](const Dex &dex) { return dexsplit::model::pool_stats(dex); },
            "The pool sizes the model would write (see PoolStats).")
        .def_property_readonly(
            "class_descriptors",
            [](const Dex &dex) {
                std::vector<std::string> out;
                out.reserve(dex.classes.size());
                for (const auto &cls : dex.classes)
                    out.push_back(cls.type);
                return out;
            },
            "Every class's descriptor, in model order.")
        .def(
            "copy_class",
            [](Dex &dst, const Dex &src, std::string_view descriptor) {
                if (dst.find_class(descriptor) != nullptr)
                    throw py::value_error(std::string("destination already has class ") +
                                          std::string(descriptor));
                const auto *cls = src.find_class(descriptor);
                if (cls == nullptr)
                    throw py::value_error(std::string("source has no class ") +
                                          std::string(descriptor));
                dst.classes.push_back(*cls);
            },
            py::arg("src"), py::arg("descriptor"),
            "Copy the class from src into this model, leaving src unchanged.")
        .def(
            "write",
            [](const Dex &dex) {
                auto result = dexsplit::model::write(dex);
                if (!result)
                    raise_model_error(result.error());
                return py::bytes(reinterpret_cast<const char *>(result->data()), result->size());
            },
            "The model as DEX bytes.  Raises ValueError if a pool overflows or the model is "
            "invalid.");
}

} // namespace

PYBIND11_MODULE(_dex, m)
{
    m.doc() = "Native core of the dex splitter: the editable DEX model.";
    register_model(m);
}
