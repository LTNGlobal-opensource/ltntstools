# ltntstools, linked against the shared libraries produced by the deps/
# superbuild:
#
#   cmake -S deps -B build-deps && cmake --build build-deps
#   cmake -S . -B build && cmake --build build
#
# Point LTNTSTOOLS_DEPS_DIR at the superbuild's build directory if it is not
# ./build-deps.

cmake_minimum_required(VERSION 3.16)
project(ltntstools VERSION 1.0 LANGUAGES C CXX)

include(GNUInstallDirs)

set(LTNTSTOOLS_DEPS_DIR "${CMAKE_SOURCE_DIR}/build-deps" CACHE PATH
    "Build directory of the deps/ superbuild")
set(_deps_config "${LTNTSTOOLS_DEPS_DIR}/ltntstools-deps-config.cmake")
if(NOT EXISTS "${_deps_config}")
  message(FATAL_ERROR "${_deps_config} not found. Build the dependencies "
    "first:\n  cmake -S deps -B build-deps && cmake --build build-deps\n"
    "or set LTNTSTOOLS_DEPS_DIR to an existing deps build directory.")
endif()
include("${_deps_config}")

option(ENABLE_DEBUG "Define DEBUG=1 (debug build)" OFF)
option(ENABLE_NTT "Enable the NBA Tissot timing inspector (needs libntt)" OFF)

# asi2ip is a stub on macOS; on Linux it needs the DekTec SDK, which the
# sources expect at ../sdk-dektec (the ltntstools-build-environment layout).
set(DTAPI_SDK_DIR "${CMAKE_SOURCE_DIR}/../sdk-dektec/LinuxSDK")
if(APPLE OR EXISTS "${DTAPI_SDK_DIR}/DTAPI/Include/DTAPI.h")
  set(_dtapi_default ON)
else()
  set(_dtapi_default OFF)
endif()
option(ENABLE_DTAPI "Enable the DekTec ASI to IP tool (asi2ip)" ${_dtapi_default})

# The proprietary Nielsen SDK is optional and detected automatically.
set(NIELSEN_SDK_DIR "${CMAKE_SOURCE_DIR}/../sdk-nielsen/package" CACHE PATH
    "Nielsen decoder SDK (containing include/ and lib/)")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(_default_rpath "$ORIGIN/../lib-ltntstools;${LTNTSTOOLS_DEPS_PREFIX}/lib")
else()
  set(_default_rpath "${LTNTSTOOLS_DEPS_PREFIX}/lib")
endif()
set(LTNTSTOOLS_INSTALL_RPATH "${_default_rpath}" CACHE STRING
    "RPATH of the installed tstools_util")

add_subdirectory(src)
