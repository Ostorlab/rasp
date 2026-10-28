# yyjson, the JSON reader the runtime reads its config with, built from the vendored source archive in
# third_party/yyjson, which pack.sh makes from the official release. Only the reader is built: the writer, the
# incremental reader, the file functions, the utilities and the non-standard JSON extensions are left out.
# yyjson_api is defined empty, so yyjson's functions are hidden like the rest of the runtime's code, instead of the
# default visibility yyjson gives them.

set(RASP_YYJSON_VERSION 0.13.0)
set(RASP_YYJSON_ARCHIVE ${CMAKE_CURRENT_LIST_DIR}/../third_party/yyjson/yyjson-${RASP_YYJSON_VERSION}-source.tar.xz)
set(RASP_YYJSON_SHA256 942e874501dd67bc97077d66c2fe966968d6485ed93750d63c8c877182c03653)
set(RASP_YYJSON_DIR ${CMAKE_BINARY_DIR}/yyjson/yyjson-${RASP_YYJSON_VERSION})

file(SHA256 ${RASP_YYJSON_ARCHIVE} _rasp_yyjson_actual)
if(NOT _rasp_yyjson_actual STREQUAL RASP_YYJSON_SHA256)
  message(FATAL_ERROR
    "vendored yyjson ${RASP_YYJSON_ARCHIVE} has sha256 ${_rasp_yyjson_actual}, expected ${RASP_YYJSON_SHA256}")
endif()

if(NOT EXISTS ${RASP_YYJSON_DIR}/src/yyjson.c)
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/yyjson)
  file(ARCHIVE_EXTRACT INPUT ${RASP_YYJSON_ARCHIVE} DESTINATION ${CMAKE_BINARY_DIR}/yyjson)
endif()

enable_language(C)
set(CMAKE_C_VISIBILITY_PRESET hidden)
add_library(rasp_yyjson STATIC ${RASP_YYJSON_DIR}/src/yyjson.c)
target_include_directories(rasp_yyjson SYSTEM PUBLIC ${RASP_YYJSON_DIR}/src)
target_compile_definitions(rasp_yyjson PUBLIC
  yyjson_api=
  YYJSON_DISABLE_WRITER=1
  YYJSON_DISABLE_INCR_READER=1
  YYJSON_DISABLE_FILE=1
  YYJSON_DISABLE_UTILS=1
  YYJSON_DISABLE_NON_STANDARD=1)
