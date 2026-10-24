# Unit tests for the nic_monitor UI modules. These modules have no curses
# or deps/ dependencies, so the tests build and run without a terminal.
#
#   cmake --build build && ctest --test-dir build --output-on-failure
#
# For sanitizer runs, configure a separate build directory with
# -DLTNTSTOOLS_SANITIZE=address (ASan + UBSan) or =thread (TSan).

set(_ui_src ${PROJECT_SOURCE_DIR}/src)

function(ltntstools_ui_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE ${_ui_src} ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(${name} PRIVATE -Wall -Wextra -Wsign-compare -g)
  target_link_libraries(${name} PRIVATE Threads::Threads)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

find_package(Threads REQUIRED)

ltntstools_ui_test(test_ui_buf
  test_ui_buf.c
  ${_ui_src}/nic_monitor_ui_buf.c)

ltntstools_ui_test(test_ui_layout
  test_ui_layout.c
  ${_ui_src}/nic_monitor_ui_layout.c
  ${_ui_src}/nic_monitor_ui_buf.c)

ltntstools_ui_test(test_ui_input
  test_ui_input.c
  ${_ui_src}/nic_monitor_ui_input.c)
