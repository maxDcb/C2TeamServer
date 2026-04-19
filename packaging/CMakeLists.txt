find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(C2_RELEASE_STAGING_ROOT "${CMAKE_BINARY_DIR}/release-staging")
set(C2_RELEASE_STAGING_DIR "${C2_RELEASE_STAGING_ROOT}/Release")

add_custom_target(stage_release_bundle
  COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/assemble_release.py"
    --source-root "${CMAKE_SOURCE_DIR}"
    --build-root "${CMAKE_BINARY_DIR}"
    --output-root "${C2_RELEASE_STAGING_DIR}"
  DEPENDS TeamServer protocol_python_stubs
  COMMENT "Staging release bundle"
  VERBATIM
)
