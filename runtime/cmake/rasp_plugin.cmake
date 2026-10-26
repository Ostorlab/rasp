# rasp_add_plugin(<name> SOURCES <source>...): builds a runtime plugin, the library that rasp/plugin.h describes.
#
# <name> must match [a-z][a-z0-9_]{0,31}. The plugin is the target rasp_plugin_<name>, built as:
# - on Android, the shared library librasp_plugin_<name>.so;
# - on iOS, the framework rasp_plugin_<name>.framework, whose binary is rasp_plugin_<name> and whose install name is
#   @rpath/rasp_plugin_<name>.framework/rasp_plugin_<name>;
# - anywhere else, such as a development machine for the tests, the shared library librasp_plugin_<name>.so.
#
# The sources see rasp/plugin.h. They are compiled with the runtime's warning and language flags and its rules for
# shipped code, with every symbol hidden, and the library exports rasp_plugin_init and nothing else. The function is
# meant for plugins built in the runtime's CMake project, which defines those flags.

set(RASP_PLUGIN_VERSION_SCRIPT ${CMAKE_BINARY_DIR}/rasp_plugin.map)
file(CONFIGURE OUTPUT ${RASP_PLUGIN_VERSION_SCRIPT} CONTENT [=[
{
  global: rasp_plugin_init;
  local: *;
};
]=])

function(rasp_add_plugin name)
  cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "SOURCES")
  string(LENGTH "${name}" name_length)
  if(NOT name MATCHES "^[a-z][a-z0-9_]*$" OR name_length GREATER 32)
    message(FATAL_ERROR "the plugin name '${name}' doesn't match [a-z][a-z0-9_]{0,31}")
  endif()
  if(NOT arg_SOURCES)
    message(FATAL_ERROR "the plugin ${name} has no SOURCES")
  endif()

  set(target rasp_plugin_${name})
  add_library(${target} SHARED ${arg_SOURCES})
  target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../core/include)
  target_link_libraries(${target} PRIVATE rasp_warnings rasp_language rasp_shipped)
  set_target_properties(${target} PROPERTIES
    OUTPUT_NAME ${target}
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)

  if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    string(REPLACE "_" "-" identifier ${name})
    set_target_properties(${target} PROPERTIES
      FRAMEWORK TRUE
      INSTALL_NAME_DIR "@rpath"
      BUILD_WITH_INSTALL_NAME_DIR ON
      MACOSX_FRAMEWORK_IDENTIFIER co.ostorlab.rasp.plugin.${identifier}
      MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
      MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
      MACOSX_FRAMEWORK_INFO_PLIST ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../ios/Info.plist.in)
    target_link_options(${target} PRIVATE "LINKER:-exported_symbol,_rasp_plugin_init")
  else()
    target_link_options(${target} PRIVATE "LINKER:--version-script=${RASP_PLUGIN_VERSION_SCRIPT}"
      "LINKER:--exclude-libs,ALL")
    set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS ${RASP_PLUGIN_VERSION_SCRIPT})
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    target_link_options(${target} PRIVATE $<$<CONFIG:Release>:-Wl,--strip-all>)
  endif()
endfunction()
