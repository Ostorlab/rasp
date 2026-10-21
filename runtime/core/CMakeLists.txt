configure_file(include/rasp/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/rasp/version.h @ONLY)

add_library(rasp_core STATIC src/observation.cpp)
target_include_directories(rasp_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include)
target_link_libraries(rasp_core PRIVATE rasp_warnings rasp_language rasp_shipped)

if(RASP_LOGGING)
  target_compile_definitions(rasp_core PUBLIC RASP_LOGGING_ENABLED=true)
else()
  target_compile_definitions(rasp_core PUBLIC RASP_LOGGING_ENABLED=false)
endif()
