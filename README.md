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

## Dependencies
	* libltntstools
	* ncurses
	* libdvbpsi

