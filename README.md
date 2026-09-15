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
    ./autogen.sh --build
    ./configure --enable-shared=no
    make

## tstools_nic_monitor REST API

The REST API is disabled by default. Enable it with `--rest-api-port <port>` when starting `tstools_nic_monitor`.

Example startup:

    tstools_nic_monitor -i eth0 -M --rest-api-port 9601

Available endpoints:

    GET /api/transport-streams
    GET /api/transport-pids
    GET /openapi.json

Sample `curl` commands:

    curl -s http://127.0.0.1:9601/api/transport-streams
    curl -s http://127.0.0.1:9601/api/transport-pids
    curl -s http://127.0.0.1:9601/openapi.json

Pretty-print responses with `jq`:

    curl -s http://127.0.0.1:9601/api/transport-streams | jq .
    curl -s http://127.0.0.1:9601/api/transport-pids | jq .

`/api/transport-streams` reports each detected stream's protocol type, source and destination addresses, bitrate, transport packet count, CC error count, IAT high water mark, and flags. `/api/transport-pids` reports the per-PID statistics for each stream, matching the PID report exposed by the interactive `P` command.

## Dependencies
	* libltntstools
	* ncurses
	* libdvbpsi
