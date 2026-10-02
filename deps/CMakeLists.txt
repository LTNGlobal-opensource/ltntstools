# Superbuild for the third-party dependencies vendored as git submodules
# under deps/.
#
#   cmake -S deps -B build-deps
#   cmake --build build-deps
#
# Every dependency is staged (rsync, without .git) into the build tree before
# it is patched/configured/built, so the submodule checkouts are never
# modified by in-source autotools builds. Results are installed into
# DEPS_PREFIX, which plays the same role as target-root/usr in the parent
# build environment.
#
# Patches: any *.patch files in deps/patches/<name>/ are applied (sorted,
# patch -p1) to the staged copy of <name> before it is configured, on every
# platform. On macOS, deps/patches/<name>/darwin/*.patch are applied after
# those.

cmake_minimum_required(VERSION 3.16)
project(ltntstools-deps NONE)

include(ExternalProject)
include(ProcessorCount)

set(DEPS_PREFIX "${CMAKE_BINARY_DIR}/target-root/usr" CACHE PATH
    "Install prefix for the built dependencies")
option(DEPS_STRICT_ORDER
    "Build dependencies strictly one after another in the documented order" ON)

ProcessorCount(_ncpu)
if(_ncpu EQUAL 0)
  set(_ncpu 4)
endif()
set(DEPS_JOBS ${_ncpu} CACHE STRING "Parallel jobs used inside each dependency build")

# find_program(... REQUIRED) needs CMake 3.18; check by hand for 3.16.
find_program(RSYNC rsync)
find_program(MAKE_EXECUTABLE NAMES gmake make)
find_program(PATCH_EXECUTABLE patch)
find_program(LIBTOOLIZE_EXECUTABLE NAMES glibtoolize libtoolize)
foreach(_tool RSYNC MAKE_EXECUTABLE PATCH_EXECUTABLE LIBTOOLIZE_EXECUTABLE)
  if(NOT ${_tool})
    message(FATAL_ERROR "Required tool not found: ${_tool}")
  endif()
endforeach()

set(_make ${MAKE_EXECUTABLE} -j${DEPS_JOBS})

# Several autogen.sh scripts call 'libtoolize' by name. Homebrew only ships
# it as 'glibtoolize', so expose it under the expected name.
set(_tools_dir "${CMAKE_BINARY_DIR}/tools")
file(MAKE_DIRECTORY ${_tools_dir})
file(CREATE_LINK ${LIBTOOLIZE_EXECUTABLE} ${_tools_dir}/libtoolize SYMBOLIC)
set(_autogen ${CMAKE_COMMAND} -E env "PATH=${_tools_dir}:$ENV{PATH}"
    ./autogen.sh --build)

# Environment for autotools/configure-script based projects so they find
# what earlier steps installed into DEPS_PREFIX.
set(_env ${CMAKE_COMMAND} -E env
    "PKG_CONFIG_PATH=${DEPS_PREFIX}/lib/pkgconfig"
    "CFLAGS=-I${DEPS_PREFIX}/include"
    "CPPFLAGS=-I${DEPS_PREFIX}/include"
    "LDFLAGS=-L${DEPS_PREFIX}/lib")

# Common arguments for CMake based projects.
set(_cmake_args
    -DCMAKE_INSTALL_PREFIX=${DEPS_PREFIX}
    # Set all three: some projects (srt) skip GNUInstallDirs when
    # CMAKE_INSTALL_LIBDIR alone is given, leaving the others empty.
    -DCMAKE_INSTALL_BINDIR=bin
    -DCMAKE_INSTALL_LIBDIR=lib
    -DCMAKE_INSTALL_INCLUDEDIR=include
    -DCMAKE_INSTALL_NAME_DIR=${DEPS_PREFIX}/lib
    -DCMAKE_INSTALL_RPATH=${DEPS_PREFIX}/lib
    -DCMAKE_PREFIX_PATH=${DEPS_PREFIX}
    -DCMAKE_BUILD_TYPE=Release
    # Several pinned projects declare a cmake_minimum_required older than
    # CMake 4 accepts.
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5)

set(_previous "")

# ltn_dep(<name> [BUILD_IN_SOURCE] [SOURCE <dir>] <ExternalProject args>...)
#
# Wraps ExternalProject_Add with the staging, patching, logging and ordering
# conventions shared by every dependency. SOURCE is relative to deps/ and
# defaults to <name>.
function(ltn_dep name)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "BUILD_IN_SOURCE" "SOURCE" "")
  if(NOT ARG_SOURCE)
    set(ARG_SOURCE ${name})
  endif()
  set(_origin "${CMAKE_CURRENT_SOURCE_DIR}/${ARG_SOURCE}")
  file(GLOB _origin_contents "${_origin}/*")
  if(NOT _origin_contents)
    message(FATAL_ERROR "${_origin} is empty. "
      "Run 'git submodule update --init --recursive'.")
  endif()

  set(_src "${CMAKE_BINARY_DIR}/src/${name}")
  set(_patch_dir "${CMAKE_CURRENT_SOURCE_DIR}/patches/${name}")
  file(GLOB _patches CONFIGURE_DEPENDS "${_patch_dir}/*.patch")
  list(SORT _patches)
  if(APPLE)
    file(GLOB _darwin_patches CONFIGURE_DEPENDS "${_patch_dir}/darwin/*.patch")
    list(SORT _darwin_patches)
    list(APPEND _patches ${_darwin_patches})
  endif()
  set(_patch_cmd PATCH_COMMAND ${CMAKE_COMMAND} -E true)
  foreach(_p IN LISTS _patches)
    list(APPEND _patch_cmd COMMAND ${PATCH_EXECUTABLE} -p1 -i ${_p})
  endforeach()

  set(_depends "")
  if(DEPS_STRICT_ORDER AND _previous)
    set(_depends DEPENDS ${_previous})
  endif()

  # CMake based projects (identified by CMAKE_ARGS) also need PKG_CONFIG_PATH,
  # or pkg_check_modules() can resolve e.g. a Homebrew OpenSSL instead.
  set(_cmake_command "")
  if("CMAKE_ARGS" IN_LIST ARG_UNPARSED_ARGUMENTS)
    set(_cmake_command CMAKE_COMMAND ${CMAKE_COMMAND} -E env
        "PKG_CONFIG_PATH=${DEPS_PREFIX}/lib/pkgconfig" ${CMAKE_COMMAND})
  endif()

  set(_in_source "")
  if(ARG_BUILD_IN_SOURCE)
    set(_in_source BUILD_IN_SOURCE 1)
  endif()

  ExternalProject_Add(${name}
    PREFIX            ${CMAKE_BINARY_DIR}/${name}
    SOURCE_DIR        ${_src}
    DOWNLOAD_COMMAND  ${RSYNC} -a --delete --exclude=.git
                      ${_origin}/ ${_src}/
    ${_patch_cmd}
    ${_in_source}
    ${_cmake_command}
    ${_depends}
    LOG_DOWNLOAD 1 LOG_PATCH 1 LOG_CONFIGURE 1 LOG_BUILD 1 LOG_INSTALL 1
    LOG_OUTPUT_ON_FAILURE 1
    ${ARG_UNPARSED_ARGUMENTS})

  # Editing a patch re-stages pristine sources so it is applied cleanly.
  if(_patches)
    ExternalProject_Add_StepDependencies(${name} download ${_patches})
  endif()

  set(_previous ${name} PARENT_SCOPE)
endfunction()

# 0. libdvbpsi (shared), required by libltntstools. Built from the
#    submodule nested inside libltntstools so its version follows the
#    libltntstools pin.
ltn_dep(libdvbpsi BUILD_IN_SOURCE
  SOURCE libltntstools/rust/libltntstools-sys/libdvbpsi
  CONFIGURE_COMMAND ./bootstrap
            COMMAND ${_env} ./configure --prefix=${DEPS_PREFIX}
                    --enable-shared --disable-static
  BUILD_COMMAND     ${_make}
  INSTALL_COMMAND   ${MAKE_EXECUTABLE} install)

# 1. libltntstools (shared)
ltn_dep(libltntstools BUILD_IN_SOURCE
  CONFIGURE_COMMAND ${_autogen}
            COMMAND ${_env} ./configure --prefix=${DEPS_PREFIX}
                    --enable-shared --disable-static
  BUILD_COMMAND     ${_make}
  INSTALL_COMMAND   ${MAKE_EXECUTABLE} install)

# 2. librdkafka (shared). OpenSSL is built after this step, so SSL support
#    is disabled rather than silently picking up a system OpenSSL.
#    On macOS, use the bundled lz4 and drop zstd so it does not link
#    Homebrew's copies.
set(_rdkafka_darwin_args "")
if(APPLE)
  set(_rdkafka_darwin_args -DWITH_ZSTD=OFF -DENABLE_LZ4_EXT=OFF)
endif()
ltn_dep(librdkafka
  CMAKE_ARGS ${_cmake_args}
    -DRDKAFKA_BUILD_STATIC=OFF
    -DRDKAFKA_BUILD_EXAMPLES=OFF
    -DRDKAFKA_BUILD_TESTS=OFF
    -DWITH_SSL=OFF
    -DWITH_SASL=OFF
    ${_rdkafka_darwin_args})

# 3. OpenSSL (shared)
ltn_dep(openssl
  CONFIGURE_COMMAND <SOURCE_DIR>/Configure --prefix=${DEPS_PREFIX} --libdir=lib
                    shared no-docs no-tests
  BUILD_COMMAND     ${_make}
  INSTALL_COMMAND   ${MAKE_EXECUTABLE} install_sw)

# 4. json-c (shared)
ltn_dep(json-c
  CMAKE_ARGS ${_cmake_args}
    -DBUILD_SHARED_LIBS=ON
    -DBUILD_TESTING=OFF
    # The pinned json-c wrongly detects -Bsymbolic-functions as supported
    # by the macOS linker, which then fails the link.
    -DDISABLE_BSYMBOLIC=ON)

# 5. libzvbi (shared)
ltn_dep(libzvbi BUILD_IN_SOURCE
  CONFIGURE_COMMAND ${_env} ./configure --prefix=${DEPS_PREFIX}
                    --enable-shared --disable-static
  BUILD_COMMAND     ${_make}
  INSTALL_COMMAND   ${MAKE_EXECUTABLE} install)

# 6. libwebsockets (static)
ltn_dep(libwebsockets
  CMAKE_ARGS ${_cmake_args}
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DLWS_WITH_SSL=OFF
    -DLWS_WITH_SHARED=OFF
    -DLWS_WITH_STATIC=ON
    -DLWS_WITHOUT_TESTAPPS=ON
    -DLWS_WITHOUT_TEST_SERVER=ON
    -DLWS_WITHOUT_TEST_SERVER_EXTPOLL=ON
    -DLWS_WITHOUT_TEST_PING=ON
    -DLWS_WITHOUT_TEST_CLIENT=ON
    -DLWS_WITH_MINIMAL_EXAMPLES=OFF)

# 7. FFmpeg (shared). Same options as the parent build.sh shared build,
#    minus --enable-libsrt since srt is built after FFmpeg.
#    On macOS, keep libavdevice/ffplay from linking Homebrew's SDL2 and xcb.
set(_ffmpeg_darwin_args "")
if(APPLE)
  set(_ffmpeg_darwin_args --disable-sdl2 --disable-libxcb)
endif()
ltn_dep(ffmpeg
  CONFIGURE_COMMAND ${_env} <SOURCE_DIR>/configure --prefix=${DEPS_PREFIX}
                    --enable-shared --disable-static
                    --disable-iconv
                    --disable-audiotoolbox --disable-videotoolbox
                    --disable-avfoundation
                    --disable-vaapi --disable-vdpau
                    ${_ffmpeg_darwin_args}
  BUILD_COMMAND     ${_make}
  INSTALL_COMMAND   ${MAKE_EXECUTABLE} install)

# 8. libklvanc (shared)
ltn_dep(libklvanc BUILD_IN_SOURCE
  CONFIGURE_COMMAND ${_autogen}
            COMMAND ${_env} ./configure --prefix=${DEPS_PREFIX}
                    --enable-shared --disable-static
  BUILD_COMMAND     ${_make}
  INSTALL_COMMAND   ${MAKE_EXECUTABLE} install)

# 9. libklscte35 (shared)
ltn_dep(libklscte35 BUILD_IN_SOURCE
  CONFIGURE_COMMAND ${_autogen}
            COMMAND ${_env} ./configure --prefix=${DEPS_PREFIX}
                    --enable-shared --disable-static
  BUILD_COMMAND     ${_make}
  INSTALL_COMMAND   ${MAKE_EXECUTABLE} install)

# 10. srt (shared). Required by ltntstools (srt_transmit.c). Built last so it
#     links against the OpenSSL built above. FFmpeg is therefore built
#     without --enable-libsrt.
ltn_dep(srt
  CMAKE_ARGS ${_cmake_args}
    -DENABLE_SHARED=ON
    -DENABLE_STATIC=OFF
    -DENABLE_APPS=OFF
    -DENABLE_ENCRYPTION=ON
    -DUSE_ENCLIB=openssl
    -DOPENSSL_ROOT_DIR=${DEPS_PREFIX})

# Paths needed by the top-level ltntstools build. It compiles against private
# FFmpeg headers (libavcodec/golomb.h, libavutil/internal.h), which need the
# patched FFmpeg sources plus the config.h generated in FFmpeg's build tree.
ExternalProject_Get_Property(ffmpeg SOURCE_DIR BINARY_DIR)
file(WRITE ${CMAKE_BINARY_DIR}/ltntstools-deps-config.cmake
"set(LTNTSTOOLS_DEPS_PREFIX \"${DEPS_PREFIX}\")
set(LTNTSTOOLS_FFMPEG_SOURCE_DIR \"${SOURCE_DIR}\")
set(LTNTSTOOLS_FFMPEG_BUILD_DIR \"${BINARY_DIR}\")
")
