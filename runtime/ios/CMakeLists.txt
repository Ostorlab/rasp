add_library(RaspRuntime SHARED
  src/entry.cpp
  src/monitoring.cpp
  src/checks/debugger.cpp
  src/checks/hooks.cpp
  src/checks/jailbreak.cpp
  src/checks/mitm.cpp)
target_include_directories(RaspRuntime PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(RaspRuntime PRIVATE rasp_core rasp_warnings rasp_language rasp_shipped)
set_source_files_properties(src/entry.cpp PROPERTIES COMPILE_OPTIONS -Wno-global-constructors)

if(RASP_LOGGING)
  target_sources(RaspRuntime PRIVATE src/util/logging.cpp)
endif()

set_target_properties(RaspRuntime PROPERTIES
  FRAMEWORK TRUE
  INSTALL_NAME_DIR "@rpath"
  BUILD_WITH_INSTALL_NAME_DIR ON
  MACOSX_FRAMEWORK_IDENTIFIER co.ostorlab.rasp.runtime
  MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
  MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
  MACOSX_FRAMEWORK_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in)
