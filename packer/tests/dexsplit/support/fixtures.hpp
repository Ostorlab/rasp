// Access to the DEX files under fixtures/.

#pragma once

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace dexsplit::support {

inline std::string fixture_path(std::string_view name)
{
    return std::string(DEXSPLIT_FIXTURES "/").append(name);
}

inline std::vector<uint8_t> load_fixture(std::string_view name)
{
    const std::string path = fixture_path(name);
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Cannot open: " + path);
    file.seekg(0, std::ios::end);
    auto size = static_cast<std::size_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(size);
    file.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(size));
    return buf;
}

} // namespace dexsplit::support
