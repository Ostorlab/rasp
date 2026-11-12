#include <filesystem>
#include <iostream>

#include "feature_fixture.hpp"
#include "model/io.hpp"

/// Emit independently inspectable DEX fixtures from the same production writer under test.
int main(int argc, char** argv) try {
  if (argc != 2) {
    return 2;
  }
  std::filesystem::create_directories(argv[1]);
  for (uint32_t version : {35U, 37U, 38U, 39U, 40U}) {
    dexsplit::budget::Scope scope;
    auto dex = dexsplit::test::feature_fixture(version);
    auto name = std::filesystem::path(argv[1]) / ("feature-0" + std::to_string(version) + ".dex");
    auto result = dexsplit::model::write_file(dex, dexsplit::budget::String(name.string()));
    if (!result) {
      std::cerr << result.error().message << '\n';
      return 1;
    }
  }
  {
    dexsplit::budget::Scope scope;
    auto unicode = dexsplit::test::feature_fixture(39);
    unicode.classes[0].type = "Lfixture/\xF0\x9D\x92\x9C;";
    auto path = std::filesystem::path(argv[1]) / "unicode-039.dex";
    auto result = dexsplit::model::write_file(unicode, dexsplit::budget::String(path.string()));
    if (!result) {
      return 1;
    }
  }
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << "\n";
  return 1;
}
