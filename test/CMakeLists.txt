cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(winchecksec_test)

file(
  GLOB_RECURSE WINCHECKSEC_TEST_SOURCES
  LIST_DIRECTORIES false
  *.h *.cpp
)

add_executable("${PROJECT_NAME}" ${WINCHECKSEC_TEST_SOURCES})
add_test(NAME "${PROJECT_NAME}" COMMAND "${PROJECT_NAME}")
target_link_libraries("${PROJECT_NAME}" PUBLIC winchecksec gtest)
target_compile_definitions(
  "${PROJECT_NAME}" PRIVATE WINCHECKSEC_TEST_ASSETS="${CMAKE_CURRENT_SOURCE_DIR}/assets"
)

# CLI integration tests. Each runs the winchecksec binary through
# cli-test.cmake, which checks the exit code and (optionally) stdout/stderr.
set(CLI_TEST_DRIVER "${CMAKE_CURRENT_SOURCE_DIR}/cli-test.cmake")
set(CLI_ASSETS "${CMAKE_CURRENT_SOURCE_DIR}/assets")

# winchecksec_cli_test(<name> EXPECT_CODE <code> [EXPECT_STDOUT <regex>]
#                      [EXPECT_STDERR <regex>] ARGS <arg>...)
function(winchecksec_cli_test name)
  cmake_parse_arguments(CLI "" "EXPECT_CODE;EXPECT_STDOUT;EXPECT_STDERR" "ARGS"
                        ${ARGN}
  )

  # Pack the argument list with a separator that survives CMake list
  # expansion; cli-test.cmake unpacks it.
  string(REPLACE ";" "|" CLI_ARGS_PACKED "${CLI_ARGS}")

  set(defs
      -DCLI_EXE=$<TARGET_FILE:winchecksec-bin> "-DCLI_ARGS=${CLI_ARGS_PACKED}"
      -DCLI_EXPECT_CODE=${CLI_EXPECT_CODE}
  )
  if(DEFINED CLI_EXPECT_STDOUT)
    list(APPEND defs "-DCLI_EXPECT_STDOUT=${CLI_EXPECT_STDOUT}")
  endif()
  if(DEFINED CLI_EXPECT_STDERR)
    list(APPEND defs "-DCLI_EXPECT_STDERR=${CLI_EXPECT_STDERR}")
  endif()

  add_test(NAME "cli-${name}" COMMAND ${CMAKE_COMMAND} ${defs} -P
                                      "${CLI_TEST_DRIVER}"
  )
endfunction()

winchecksec_cli_test(
  valid-signature EXPECT_CODE 0 ARGS "${CLI_ASSETS}/32/pegoat-authenticode.exe"
)

winchecksec_cli_test(unsigned EXPECT_CODE 2 ARGS "${CLI_ASSETS}/32/pegoat.exe")

winchecksec_cli_test(
  tampered-signature EXPECT_CODE 3 ARGS
  "${CLI_ASSETS}/32/pegoat-authenticode-tampered.exe"
)

winchecksec_cli_test(
  missing-intermediate EXPECT_CODE 3 ARGS
  "${CLI_ASSETS}/32/pegoat-authenticode-missing-intermediate.exe"
)

winchecksec_cli_test(unparsable EXPECT_CODE 4 ARGS "${CLI_ASSETS}/not-a-pe.txt")

winchecksec_cli_test(usage EXPECT_CODE 1 ARGS)

# Batch mode: the process must not stop at the first failing input, and the
# exit code must reflect the most severe per-input outcome.
winchecksec_cli_test(
  batch-most-severe
  EXPECT_CODE
  4
  EXPECT_STDOUT
  "Summary: 4 file"
  ARGS
  "${CLI_ASSETS}/32/pegoat-authenticode.exe"
  "${CLI_ASSETS}/32/pegoat.exe"
  "${CLI_ASSETS}/32/pegoat-authenticode-tampered.exe"
  "${CLI_ASSETS}/not-a-pe.txt"
)

winchecksec_cli_test(
  batch-unsigned-aggregate EXPECT_CODE 2 ARGS
  "${CLI_ASSETS}/32/pegoat-authenticode.exe" "${CLI_ASSETS}/32/pegoat.exe"
)

winchecksec_cli_test(
  batch-invalid-aggregate EXPECT_CODE 3 ARGS "${CLI_ASSETS}/32/pegoat.exe"
  "${CLI_ASSETS}/32/pegoat-authenticode-tampered.exe"
)

# JSON mode: parse failures are reported as per-file error entries with a
# stable field order, alongside a batch summary identical to the text mode's.
winchecksec_cli_test(
  json-error-entry
  EXPECT_CODE
  4
  EXPECT_STDOUT
  "\"results\":.{\"path\":\".*pegoat.exe\",\"mitigations\":.*{\"path\":\".*not-a-pe.txt\",\"error\":"
  ARGS
  -j
  "${CLI_ASSETS}/32/pegoat.exe"
  "${CLI_ASSETS}/not-a-pe.txt"
)

winchecksec_cli_test(
  json-summary
  EXPECT_CODE
  2
  EXPECT_STDOUT
  "\"summary\":{\"total\":2,\"ok\":1,\"unsigned\":1,\"invalidSignature\":0,\"failed\":0}"
  ARGS
  -j
  "${CLI_ASSETS}/32/pegoat-authenticode.exe"
  "${CLI_ASSETS}/32/pegoat.exe"
)
