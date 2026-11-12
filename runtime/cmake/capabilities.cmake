# The producer runs after linking, using the same catalogue and validator as the packaging consumer.
# It also runs on incremental builds so catalogue-only changes never leave stale sidecars.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

function(rasp_capabilities target platform abi minimum_os)
  add_custom_target(${target}_capabilities ALL
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/capabilities.py emit
      $<TARGET_FILE:${target}> ${platform} ${abi} ${minimum_os}
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/local_policy_support.py emit
      $<TARGET_FILE:${target}> ${platform} ${abi} ${minimum_os}
    DEPENDS ${target}
    VERBATIM)
  if(platform STREQUAL "ios")
    install(DIRECTORY $<TARGET_BUNDLE_DIR:${target}>
      DESTINATION rasp_packer/ios/resources COMPONENT runtime)
  else()
    install(FILES $<TARGET_FILE:${target}> $<TARGET_FILE:${target}>.capabilities.json $<TARGET_FILE:${target}>.local-policy.json
      DESTINATION rasp_packer/android/resources/lib/${abi} COMPONENT runtime)
    install(FILES ${PROJECT_SOURCE_DIR}/core/include/rasp/local_policy_host.h
      DESTINATION rasp_packer/android/resources/include/rasp COMPONENT runtime)
    install(FILES ${PROJECT_SOURCE_DIR}/android/stub/co/ostorlab/rasp/RuntimeBridge.java
      DESTINATION rasp_packer/android/resources/compile-only/co/ostorlab/rasp COMPONENT runtime)
  endif()
endfunction()
