# Features / ISO13818-1 MPEG-TS Transport Tools
    * nic_monitor: Monitor 100's of streams concurrently for service abnormalities
    * asi2ip: A low jitter ASI to IP conversion tool, leveraging the DekTec ASI family of cards.
	* nielsen_inspector: Find and extract nielsen codes (requires proprietary SDK).
    * scte35_inspector: Extract, parse and display SCTE35 data from MPEG-TS transport streams.
    * bitrate_smoother: Take a burstly UDP stream in, output a smoother UDP stream.
    * clock_inspector: Analyze transport files, look for PTS/DTS/PCR abnormalities
	* iat_tester: TOol to test network / kernel schedule streaming jitter performance.
    * igmp_join: Issue IGMP multicast joins
    * pcap2ts: Extract transport streams from pcap recordings.
    * pes_inspector: Extract / parse PES headers from streams.
	* sei_unregistered: Find unregistered SEI messages in a stransport stream.
    * si_inspector: Extract detailed service information from SPTS / MPTS streams.
    * si_streammodel: Tool that demonstrates the libltntstools framework
    * slicer: For very large TS recordings, index the file by PCR then selectively extract
    * stream_verifier: Detect any kind of bit mangling or loss problems through transport.
    * tr101290_analyzer: Demonstrates how to use the framework. See nic_monitor also.
    * udp_capture: Deprecated. Use nic_monitor tool instead.

# LICENSE

	LGPL-V2.1
	See the included lgpl-2.1.txt for the complete license agreement.

## Compilation

### 1. Fetch the dependency sources

The dependencies are git submodules under `deps/`. libdvbpsi is a submodule
nested inside libltntstools, so its version follows the libltntstools pin.

    git submodule update --init
    git -C deps/libltntstools submodule update --init

Avoid `git submodule update --init --recursive`: it also checks out OpenSSL's
test and fuzzing submodules (over 1GB), which the build does not use.

### 2. Build the dependencies (CMake)

    cmake -S deps -B build-deps
    cmake --build build-deps

This builds, in order: libdvbpsi, libltntstools, librdkafka, OpenSSL, json-c,
libzvbi, libwebsockets (static), FFmpeg, libklvanc, libklscte35 and srt, all
shared unless noted. Results are installed into `build-deps/target-root/usr`; use
`-DDEPS_PREFIX=<path>` to install elsewhere.

Each dependency is copied into the build tree before it is built, so the
submodule checkouts are never modified. Patches in `deps/patches/<name>/` are
applied to every build; patches in `deps/patches/<name>/darwin/` are applied
only on macOS.

Useful options:

    -DDEPS_STRICT_ORDER=OFF   Let dependencies build independently instead of
                              stopping at the first failure.
    -DDEPS_JOBS=<n>           Parallel jobs used inside each dependency build.

After moving a submodule to a new commit, delete
`build-deps/<name>/src/<name>-stamp/<name>-download` (or use a fresh build
directory) so the new sources are copied in.

### 3. Build ltntstools (CMake)

    cmake -S . -B build
    cmake --build build

This links `tstools_util` against the shared libraries from step 2 and creates
the `tstools_*` symlinks next to it in `build/src/`. Configuration fails if any
of those libraries would come from somewhere other than the step 2 build.

    cmake --install build --prefix <dir>

installs `tstools_util` and the symlinks into `<dir>/bin`.

Useful options:

    -DLTNTSTOOLS_DEPS_DIR=<dir>   Step 2 build directory (default: ./build-deps).
    -DENABLE_DTAPI=ON|OFF         DekTec asi2ip tool. On by default on macOS (a
                                  stub) and on Linux when ../sdk-dektec exists.
    -DENABLE_NTT=ON               NBA Tissot timing inspector (needs libntt).
    -DNIELSEN_SDK_DIR=<dir>       Nielsen SDK; enabled automatically if found
                                  (default: ../sdk-nielsen/package).
    -DENABLE_DEBUG=ON             Define DEBUG=1.
    -DLTNTSTOOLS_INSTALL_RPATH=.. RPATH of the installed binary.

If an earlier autotools build left `src/clock_inspector_ws_html.h` behind,
delete it; otherwise it is used instead of the header CMake generates.

The autotools build (`./autogen.sh --build && ./configure && make`) is still
present but expects the ltntstools-build-environment layout
(`../../target-root`, `../../ffmpeg`) rather than the step 2 output.

### Build prerequisites

    cmake (3.16+), make, autoconf, automake, libtool, pkg-config, rsync, patch,
    and libpcap, zlib, libcurl and ncurses development headers.

On macOS:

    brew install cmake autoconf automake libtool pkg-config

## tstools_nic_monitor REST API

The REST API is disabled by default. Enable it with `--rest-api-port <port>` when starting `tstools_nic_monitor`.

Example startup:

    tstools_nic_monitor -i eth0 -M --rest-api-port 9601

Available endpoints:

    GET /api/transport-streams
    GET /api/transport-pids
    POST /api/reset
    GET /openapi.json

Sample `curl` commands:

    curl -s http://127.0.0.1:9601/api/transport-streams
    curl -s http://127.0.0.1:9601/api/transport-pids
    curl -s -X POST http://127.0.0.1:9601/api/reset
    curl -s http://127.0.0.1:9601/openapi.json

Pretty-print responses with `jq`:

    curl -s http://127.0.0.1:9601/api/transport-streams | jq .
    curl -s http://127.0.0.1:9601/api/transport-pids | jq .
    curl -s -X POST http://127.0.0.1:9601/api/reset | jq .

`/api/transport-streams` reports each detected stream's protocol type, source and destination addresses, bitrate, transport packet count, CC error count, IAT high water mark, and flags. `/api/transport-pids` reports the per-PID statistics for each stream, matching the PID report exposed by the interactive `P` command. `POST /api/reset` resets the same statistics as the interactive `r` command.

## Dependencies
	Built from deps/ (see Compilation):
	* libltntstools
	* libdvbpsi
	* librdkafka
	* openssl
	* json-c
	* libzvbi
	* libwebsockets
	* ffmpeg
	* libklvanc
	* libklscte35
	* srt

	From the system:
	* libpcap
	* zlib
	* libcurl
	* ncurses
