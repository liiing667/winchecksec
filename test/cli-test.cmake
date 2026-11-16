# CLI integration test driver.
#
# Expected definitions:
#   CLI_EXE           - path to the winchecksec executable
#   CLI_ARGS          - arguments to pass to the executable (|-separated)
#   CLI_EXPECT_CODE   - expected process exit code
#   CLI_EXPECT_STDOUT - optional regex that stdout must match
#   CLI_EXPECT_STDERR - optional regex that stderr must match

if(NOT "${CLI_ARGS}" STREQUAL "")
  string(REPLACE "|" ";" CLI_ARGS "${CLI_ARGS}")
endif()

execute_process(
  COMMAND "${CLI_EXE}" ${CLI_ARGS}
  RESULT_VARIABLE code
  OUTPUT_VARIABLE out
  ERROR_VARIABLE err
)

if(NOT code EQUAL CLI_EXPECT_CODE)
  message(
    FATAL_ERROR
      "expected exit code ${CLI_EXPECT_CODE}, got ${code}\nstdout:\n${out}\nstderr:\n${err}"
  )
endif()

if(DEFINED CLI_EXPECT_STDOUT AND NOT out MATCHES "${CLI_EXPECT_STDOUT}")
  message(FATAL_ERROR "stdout does not match '${CLI_EXPECT_STDOUT}':\n${out}")
endif()

if(DEFINED CLI_EXPECT_STDERR AND NOT err MATCHES "${CLI_EXPECT_STDERR}")
  message(FATAL_ERROR "stderr does not match '${CLI_EXPECT_STDERR}':\n${err}")
endif()
