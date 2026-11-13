# Generate before compilation-database consumers run, including configure-only tidy.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/tools/cycle_catalogue.py
  ${PROJECT_SOURCE_DIR}/../packer/src/rasp_packer/capabilities.py
  ${PROJECT_SOURCE_DIR}/../packer/src/rasp_packer/checks_manifest.json)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)
execute_process(COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/cycle_catalogue.py
  ${CMAKE_CURRENT_BINARY_DIR}/include/cycle_catalogue.h COMMAND_ERROR_IS_FATAL ANY)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/tools/root_package_header.py
  ${PROJECT_SOURCE_DIR}/../packer/src/rasp_packer/android/root_manager_packages_v1.json)
execute_process(COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/root_package_header.py
  ${CMAKE_CURRENT_BINARY_DIR}/include/root_manager_packages.h COMMAND_ERROR_IS_FATAL ANY)

configure_file(include/rasp/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/rasp/version.h @ONLY)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/tools/local_policy_header.py
  ${PROJECT_SOURCE_DIR}/../packer/src/rasp_packer/local_policy.py
  ${PROJECT_SOURCE_DIR}/../packer/src/rasp_packer/local_policy_selectors_v1.json)
execute_process(COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/local_policy_header.py
  ${CMAKE_CURRENT_BINARY_DIR}/include/local_policy_selectors.h COMMAND_ERROR_IS_FATAL ANY)

add_library(rasp_core STATIC
  src/cycle.cpp
  src/decision.cpp
  src/local_policy.cpp
  src/local_policy_config.cpp
  src/local_policy_state.cpp
  src/util/uuid.cpp
  src/config.cpp
  src/embedded_config.cpp
  src/install_id.cpp
  src/private_storage.cpp
  src/observation.cpp
  src/parse_config.cpp
  src/plugins/init_plugins.cpp
  src/plugins/run_plugins.cpp
  src/util/read_file.cpp)
# The host suite exercises the POSIX clock used by its native platform too.
if(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR APPLE)
  target_link_libraries(rasp_core PRIVATE "$<LINK_LIBRARY:FRAMEWORK,Security>")
  target_include_directories(rasp_core PRIVATE ${PROJECT_SOURCE_DIR}/ios/src)
  target_sources(rasp_core PRIVATE ${PROJECT_SOURCE_DIR}/ios/src/util/cycle_clock.cpp
    ${PROJECT_SOURCE_DIR}/ios/src/util/local_policy_clock.cpp
    ${PROJECT_SOURCE_DIR}/ios/src/util/storage_flags.cpp)
else()
  target_include_directories(rasp_core PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
  target_sources(rasp_core PRIVATE ${PROJECT_SOURCE_DIR}/android/src/util/cycle_clock.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/local_policy_clock.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/storage_flags.cpp)
endif()
target_include_directories(rasp_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/posix/include)
target_include_directories(rasp_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(rasp_core PRIVATE rasp_yyjson rasp_tfpsacrypto rasp_warnings rasp_language rasp_shipped)

if(RASP_LOGGING)
  target_compile_definitions(rasp_core PUBLIC RASP_LOGGING_ENABLED=true)
else()
  target_compile_definitions(rasp_core PUBLIC RASP_LOGGING_ENABLED=false)
endif()
