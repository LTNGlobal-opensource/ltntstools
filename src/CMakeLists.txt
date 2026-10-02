find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(CURL REQUIRED)
find_package(Curses REQUIRED)
include(CheckIncludeFileCXX)

find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR "libpcap headers/library not found")
endif()

# Libraries from the deps/ superbuild, resolved through their pkg-config
# files. Each must come from LTNTSTOOLS_DEPS_PREFIX, never from a system or
# Homebrew copy that happens to be on the pkg-config search path.
set(ENV{PKG_CONFIG_PATH}
    "${LTNTSTOOLS_DEPS_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
set(_dep_modules
    libltntstools libdvbpsi json-c libklscte35 libklvanc zvbi-0.2
    libwebsockets srt
    libavformat libavcodec libavutil libswresample libswscale)
pkg_check_modules(LTN_DEPS REQUIRED IMPORTED_TARGET ${_dep_modules})

get_filename_component(_deps_libdir "${LTNTSTOOLS_DEPS_PREFIX}/lib" REALPATH)
foreach(_m IN LISTS _dep_modules)
  pkg_get_variable(_libdir ${_m} libdir)
  # libwebsockets.pc quotes its prefix; older pkg-config (0.27, CentOS 7)
  # returns those quotes as part of the value.
  string(REPLACE "\"" "" _libdir "${_libdir}")
  get_filename_component(_libdir "${_libdir}" REALPATH)
  if(NOT _libdir STREQUAL _deps_libdir)
    message(FATAL_ERROR "pkg-config module ${_m} resolved to ${_libdir}, "
      "expected ${_deps_libdir}. Is the deps/ superbuild complete?")
  endif()
endforeach()

set(_ffmpeg_src "${LTNTSTOOLS_FFMPEG_SOURCE_DIR}")
set(_ffmpeg_build "${LTNTSTOOLS_FFMPEG_BUILD_DIR}")
if(NOT EXISTS "${_ffmpeg_build}/config.h")
  message(FATAL_ERROR "${_ffmpeg_build}/config.h not found. "
    "Build the deps/ superbuild first.")
endif()

set(SRC
    tstools_util.c
    pat_inspector.c
    pmt_inspector.c
    dump.c
    base64.c
    si_inspector.c
    pcap2ts.c
    clock_inspector.c
    clock_inspector_ts.c
    clock_inspector_misc.c
    clock_inspector_pcr.c
    clock_inspector_pes.c
    clock_inspector_ws.c
    pid_drop.c
    nic_monitor.c
    nic_monitor_di.c
    nic_monitor_pcap.c
    nic_monitor_json.c
    nic_monitor_rest.c
    nic_monitor_tr101290.c
    nic_monitor_kafka.c
    parsers.c
    kbhit.c
    rtmp_analyzer.c
    tr101290_analyzer.c
    si_streammodel.c
    scte35_inspector.c
    utils.c
    iat_tester.c
    ffmpeg_metadata.cpp
    igmp_join.c
    slicer.c
    hash_index.c
    sei_unregistered.c
    stream_verifier.c
    pes_inspector.c
    bitrate_smoother.c
    nielsen_inspector.cpp
    smpte2038_inspector.c
    srt_transmit.c
    source-avio.c
    sei_latency_inspector.c
    kl-lineartrend.c
    caption_analyzer.c
    caption_analyzer_metrics.c
    langdict.c
    h264_codec_metadata.c
    h265_codec_metadata.c
    audioanalyzer.c
    nielsen-bindings.cpp
    golomb.c
    source-rcts.c
    timecode.c
    source-pcap.c
    demux_inspector.c
    splicer.c
    splicer-input.c
    splicer-input-pid.c
    splicer-output.c
    splicer-codecs.c
    avc-core.c
    avc-sps.c
    avc-pps.c
    avc-slice.c)

set(LINKBINS
    tstools_pat_inspector
    tstools_pmt_inspector
    tstools_si_inspector
    tstools_pcap2ts
    tstools_clock_inspector
    tstools_pid_drop
    tstools_nic_monitor
    tstools_rtmp_analyzer
    tstools_tr101290_analyzer
    tstools_si_streammodel
    tstools_iat_tester
    tstools_ffmpeg_metadata
    tstools_scte35_inspector
    tstools_igmp_join
    tstools_slicer
    tstools_sei_unregistered
    tstools_stream_verifier
    tstools_pes_inspector
    tstools_bitrate_smoother
    tstools_nielsen_inspector
    tstools_smpte2038_inspector
    tstools_srt_transmit
    tstools_sei_latency_inspector
    tstools_caption_analyzer
    tstools_demux_inspector
    tstools_splicer)

set(_gen "${CMAKE_CURRENT_BINARY_DIR}/generated")

# clock_inspector_ws.c embeds the web UI (previously generated with xxd).
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/clock_inspector_ws_html.h")
  message(WARNING "${CMAKE_CURRENT_SOURCE_DIR}/clock_inspector_ws_html.h "
    "(left by an autotools build) shadows the generated header. Remove it "
    "or changes to clock_inspector_ws_html/index.html will be ignored.")
endif()
add_custom_command(
  OUTPUT  ${_gen}/clock_inspector_ws_html.h
  COMMAND ${CMAKE_COMMAND}
          -DINPUT=${CMAKE_CURRENT_SOURCE_DIR}/clock_inspector_ws_html/index.html
          -DOUTPUT=${_gen}/clock_inspector_ws_html.h
          -DNAME=clock_inspector_ws_html_index_html
          -P ${PROJECT_SOURCE_DIR}/cmake/bin2c.cmake
  DEPENDS clock_inspector_ws_html/index.html ${PROJECT_SOURCE_DIR}/cmake/bin2c.cmake
  COMMENT "Embedding clock_inspector_ws_html/index.html")
list(APPEND SRC ${_gen}/clock_inspector_ws_html.h)

# GIT_VERSION is refreshed on every build, as the autotools build did.
add_custom_target(git_version
  COMMAND ${CMAKE_COMMAND} -DSOURCE_DIR=${PROJECT_SOURCE_DIR}
          -DOUTPUT=${_gen}/git_version.h
          -P ${PROJECT_SOURCE_DIR}/cmake/git-version.cmake
  BYPRODUCTS ${_gen}/git_version.h
  COMMENT "Checking git version")
set_source_files_properties(tstools_util.c clock_inspector_ws.c bitrate_smoother.c
  PROPERTIES
    COMPILE_OPTIONS "-include;${_gen}/git_version.h"
    OBJECT_DEPENDS ${_gen}/git_version.h)

add_executable(tstools_util ${SRC})
add_dependencies(tstools_util git_version)

if(ENABLE_DTAPI)
  target_sources(tstools_util PRIVATE asi2ip.cpp)
  target_compile_definitions(tstools_util PRIVATE HAVE_DTAPI=1)
  list(APPEND LINKBINS tstools_asi2ip)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(tstools_util PRIVATE
      ${DTAPI_SDK_DIR}/DTAPI/Lib/GCC4.8_CXX11_ABI0/DTAPI64.o)
  endif()
endif()

if(ENABLE_NTT)
  find_library(NTT_LIBRARY ntt HINTS ${LTNTSTOOLS_DEPS_PREFIX}/lib)
  if(NOT NTT_LIBRARY)
    message(FATAL_ERROR "ENABLE_NTT is ON but libntt was not found")
  endif()
  target_sources(tstools_util PRIVATE ntt_inspector.cpp)
  target_compile_definitions(tstools_util PRIVATE HAVE_NTT=1)
  target_link_libraries(tstools_util PRIVATE ${NTT_LIBRARY})
  list(APPEND LINKBINS tstools_ntt_inspector)
endif()

set(CMAKE_REQUIRED_INCLUDES ${NIELSEN_SDK_DIR}/include)
check_include_file_cxx(IMonitorSdkProcessor.h HAVE_IMONITORSDKPROCESSOR_H)
unset(CMAKE_REQUIRED_INCLUDES)
if(HAVE_IMONITORSDKPROCESSOR_H)
  target_compile_definitions(tstools_util PRIVATE HAVE_IMONITORSDKPROCESSOR_H=1)
  target_include_directories(tstools_util PRIVATE ${NIELSEN_SDK_DIR}/include)
  target_link_directories(tstools_util PRIVATE ${NIELSEN_SDK_DIR}/lib)
  target_link_libraries(tstools_util PRIVATE
    MonitorSdk Naes2HybridDecoder Naes2HFDecoder Naes6Decoder CBETDecoder
    NielsenAudioCore)
endif()

if(ENABLE_DEBUG)
  set(_debug 1)
else()
  set(_debug 0)
endif()

target_compile_definitions(tstools_util PRIVATE
  VERSION="${PROJECT_VERSION}"
  PROG="${PROJECT_NAME}"
  DEBUG=${_debug}
  _FILE_OFFSET_BITS=64
  _DEFAULT_SOURCE
  $<$<COMPILE_LANGUAGE:CXX>:__STDC_FORMAT_MACROS>
  $<$<COMPILE_LANGUAGE:CXX>:__STDC_CONSTANT_MACROS>
  $<$<COMPILE_LANGUAGE:CXX>:__STDC_LIMIT_MACROS>)

target_compile_options(tstools_util PRIVATE -Wall -Wsign-compare)
# The autotools build always used -O3 -g; keep that unless a build type is
# chosen explicitly.
if(NOT CMAKE_BUILD_TYPE)
  target_compile_options(tstools_util PRIVATE -O3 -g)
endif()

set_target_properties(tstools_util PROPERTIES
  CXX_STANDARD 11
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  INSTALL_RPATH "${LTNTSTOOLS_INSTALL_RPATH}")

# Same search order as the autotools build: FFmpeg's (patched) source tree
# and generated config.h first, for its private headers.
target_include_directories(tstools_util PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${_gen}
  ${_ffmpeg_src}/libavcodec
  ${_ffmpeg_src}
  ${_ffmpeg_build}
  ${LTNTSTOOLS_DEPS_PREFIX}/include
  ${PCAP_INCLUDE_DIR}
  ${CURSES_INCLUDE_DIRS})

target_link_libraries(tstools_util PRIVATE
  PkgConfig::LTN_DEPS
  ${PCAP_LIBRARY}
  ZLIB::ZLIB
  CURL::libcurl
  ${CURSES_LIBRARIES}
  Threads::Threads
  ${CMAKE_DL_LIBS}
  m)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(tstools_util PRIVATE rt)
endif()

# Every tool is tstools_util under another name.
foreach(_link IN LISTS LINKBINS)
  add_custom_command(TARGET tstools_util POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink tstools_util ${_link}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:tstools_util>
    VERBATIM)
endforeach()

install(TARGETS tstools_util RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(CODE "
  foreach(_link ${LINKBINS})
    execute_process(COMMAND \${CMAKE_COMMAND} -E create_symlink tstools_util
      \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/\${_link}\")
  endforeach()
")
