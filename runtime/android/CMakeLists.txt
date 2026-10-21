add_library(rasp SHARED
  src/entry.cpp
  src/apk/archive.cpp
  src/apk/location.cpp
  src/checks/root.cpp
  src/loader/loader.cpp
  src/payload/cipher.cpp
  src/payload/payload.cpp)
target_include_directories(rasp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(rasp PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language rasp_shipped nativehelper)
target_link_options(rasp PRIVATE -Wl,--exclude-libs,ALL)
target_link_options(rasp PRIVATE $<$<CONFIG:Release>:-Wl,--strip-all>)
set_source_files_properties(src/entry.cpp PROPERTIES COMPILE_OPTIONS -Wno-global-constructors)

if(RASP_LOGGING)
  target_sources(rasp PRIVATE src/util/logging.cpp)
  target_link_libraries(rasp PRIVATE log)
endif()
