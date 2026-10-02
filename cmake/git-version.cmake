# Write OUTPUT defining GIT_VERSION from 'git describe' in SOURCE_DIR.
# Runs on every build; OUTPUT is only rewritten when the version changes, so
# unchanged builds do not recompile its users.
#
#   cmake -DSOURCE_DIR=<dir> -DOUTPUT=<header> -P git-version.cmake

execute_process(
  COMMAND git describe --abbrev=8 --dirty --always --tags
  WORKING_DIRECTORY "${SOURCE_DIR}"
  OUTPUT_VARIABLE _version
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
  RESULT_VARIABLE _result)
if(NOT _result EQUAL 0 OR _version STREQUAL "")
  set(_version "unknown")
endif()

set(_content "#define GIT_VERSION \"${_version}\"\n")
if(EXISTS "${OUTPUT}")
  file(READ "${OUTPUT}" _old)
endif()
if(NOT _old STREQUAL _content)
  file(WRITE "${OUTPUT}" "${_content}")
endif()
