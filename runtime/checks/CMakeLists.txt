add_library(rasp_checks STATIC src/ios/jailbreak.cpp)
target_include_directories(rasp_checks PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(rasp_checks PUBLIC rasp_core PRIVATE rasp_warnings rasp_language rasp_shipped)
