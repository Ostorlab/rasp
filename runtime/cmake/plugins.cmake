# rasp_plugin(<name> SOURCES <source>...): declares a plugin to compile into the runtime. The CMakeLists.txt of each
# directory of RASP_PLUGINS calls it.
#
# <name> matches [a-z][a-z0-9_]{0,31}. The sources define the plugin, a rasp::plugins::Plugin (rasp/plugin.h), as
# `extern constexpr Plugin kPlugin` in the namespace rasp::plugins::<name>. They are built into the static library
# rasp_plugin_<name> with the runtime's own toolchain, flags and libc++, and see the runtime core's headers. The
# directory can link the libraries its plugin needs to that target.
#
# rasp_plugin_registry(<target> <name>...): builds the static library <target>, which links the plugins <name>... and
# defines rasp::plugins::compiled_in() (rasp/plugins/registry.h) as them, in that order.
#
# The directories of RASP_PLUGINS are added in order, and rasp_plugins is the registry of the plugins they declare,
# which the runtime library links.

function(rasp_plugin name)
  cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "SOURCES")
  string(LENGTH "${name}" name_length)
  if(NOT name MATCHES "^[a-z][a-z0-9_]*$" OR name_length GREATER 32)
    message(FATAL_ERROR "the plugin name '${name}' doesn't match [a-z][a-z0-9_]{0,31}")
  endif()
  if(NOT arg_SOURCES)
    message(FATAL_ERROR "the plugin ${name} has no SOURCES")
  endif()
  add_library(rasp_plugin_${name} STATIC ${arg_SOURCES})
  target_link_libraries(rasp_plugin_${name} PRIVATE rasp_core rasp_warnings rasp_language rasp_shipped)
  set_property(GLOBAL APPEND PROPERTY RASP_PLUGIN_NAMES ${name})
endfunction()

function(rasp_plugin_registry target)
  set(RASP_PLUGIN_DECLARATIONS "")
  set(addresses "")
  foreach(name IN LISTS ARGN)
    string(APPEND RASP_PLUGIN_DECLARATIONS
      "namespace rasp::plugins::${name} {\nextern const Plugin kPlugin;\n}  // namespace rasp::plugins::${name}\n\n")
    list(APPEND addresses "&${name}::kPlugin")
  endforeach()
  list(LENGTH ARGN RASP_PLUGIN_COUNT)
  list(JOIN addresses ", " RASP_PLUGIN_ADDRESSES)
  configure_file(${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../core/src/plugins/registry.cpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/${target}.cpp @ONLY)
  add_library(${target} STATIC ${CMAKE_CURRENT_BINARY_DIR}/${target}.cpp)
  target_link_libraries(${target} PUBLIC rasp_core PRIVATE rasp_warnings rasp_language rasp_shipped)
  foreach(name IN LISTS ARGN)
    target_link_libraries(${target} PRIVATE rasp_plugin_${name})
  endforeach()
endfunction()

set(rasp_plugin_index 0)
foreach(rasp_plugin_directory IN LISTS RASP_PLUGINS)
  cmake_path(ABSOLUTE_PATH rasp_plugin_directory BASE_DIRECTORY ${PROJECT_SOURCE_DIR} NORMALIZE)
  add_subdirectory(${rasp_plugin_directory} ${CMAKE_BINARY_DIR}/plugins/${rasp_plugin_index})
  math(EXPR rasp_plugin_index "${rasp_plugin_index} + 1")
endforeach()
get_property(rasp_compiled_plugins GLOBAL PROPERTY RASP_PLUGIN_NAMES)
rasp_plugin_registry(rasp_plugins ${rasp_compiled_plugins})
