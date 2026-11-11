/** Python bindings for the trimmed dex splitter's native core (dexsplit._dex). */

#include <pybind11/pybind11.h>

PYBIND11_MODULE(_dex, m)
{
    m.doc() = "Native core of the dex splitter.";
}
