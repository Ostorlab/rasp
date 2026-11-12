# The producer runs after linking, using the same catalogue and validator as the packaging consumer.
# It also runs on incremental builds so catalogue-only changes never leave stale sidecars.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

function(rasp_capabilities target platform abi minimum_os)
  add_custom_target(${target}_capabilities ALL
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/capabilities.py emit
      $<TARGET_FILE:${target}> ${platform} ${abi} ${minimum_os}
    DEPENDS ${target}
    VERBATIM)
  if(platform STREQUAL "ios")
    install(DIRECTORY $<TARGET_BUNDLE_DIR:${target}>
      DESTINATION rasp_packer/ios/resources COMPONENT runtime)
  else()
    install(FILES $<TARGET_FILE:${target}> $<TARGET_FILE:${target}>.capabilities.json
      DESTINATION rasp_packer/android/resources/lib/${abi} COMPONENT runtime)
  endif()
endfunction()
