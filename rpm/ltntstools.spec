Name:		ltntstools
Version:	1.0.0
Release:	1
Summary:	ISO13818 MPEG-TS Packet Monitor

License:	GPLv2+
URL:		www.ltnglobal.com

#BuildRequires:	
BuildRequires:	zlib-devel
BuildRequires:	libpcap-devel
BuildRequires:	ncurses-devel

Requires:	zlib
Requires:	libpcap
Requires:	ncurses

%description
A tool to capture, inspect or monitor MPEG-TS files and streams.

%files
/usr/local/bin/tstools_util
/usr/local/bin/tstools_clock_inspector
/usr/local/bin/tstools_nic_monitor
/usr/local/bin/tstools_pat_inspector
/usr/local/bin/tstools_pcap2ts
/usr/local/bin/tstools_pid_drop
/usr/local/bin/tstools_pmt_inspector
/usr/local/bin/tstools_si_inspector
/usr/local/bin/tstools_udp_capture
/usr/local/bin/tstools_rtmp_analyzer
/usr/local/bin/tstools_si_streammodel
/usr/local/bin/tstools_tr101290_analyzer
/usr/local/bin/tstools_ffmpeg_metadata
/usr/local/bin/tstools_scte35_inspector
/usr/local/bin/tstools_igmp_join
/usr/local/bin/tstools_slicer
/usr/local/bin/tstools_sei_unregistered
/usr/local/bin/tstools_stream_verifier
/usr/local/bin/tstools_pes_inspector
/usr/local/bin/tstools_iat_tester
/usr/local/bin/tstools_bitrate_smoother
/usr/local/bin/tstools_nielsen_inspector
/usr/local/bin/tstools_asi2ip
/usr/local/bin/tstools_smpte2038_inspector
/usr/local/share/man/man8/tstools_nic_monitor.8
/usr/local/share/man/man8/tstools_pcapts.8
/usr/local/share/man/man8/tstools_ffmpeg_metadata.8

%changelog
* Thu May 26 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.15.0
  tstools_udp_capture: Deprecated in v1.9.0. See tstools_igmp_join if you need IGMP tooling. 

* Wed May 25 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.14.0
  tstools_scte35_inspector: Feature. Add support for live streams via pcap/nic interfaces.
  tstools_scte35_inspector: Feature. Autodetect audio and video pids (SPTS only).
  tstools_scte35_inspector: Feature. Show the future ad break time measured in milliseconds.
  tstools_si_streammodel: Feature. Add support for url live srteams as input.
  tstools_nic_monitor: Feature. -O Don't stop recording when disk has less tha 10pct free. (Danger).
  tstools_pes_inspector: When operator doesn't ask for payload parsing, indicate this when dumping packets. Better clarity.
  tstools_pes_inspector: Behaviour change. Show PES headers by default, add an opt out argument. Helps with SMPTE2038 debug.
  general: Fixed various OSX compile time issues, disabled certain tools on OSX (asi2ip).
  tstools_smpte2038_inspector: Feature. New tool to auto-detect SMPTE2038 messages and dump them for inspection. NIC/PCAP, file or live stream.
  tstools_nic_monitor: change IAT row reporting to MAX iat measure in ms, removed current and low watermark value.
  tstools_nic_monitor: When MAX IAT exceeds 45ms, draw the UI row in red for warning, with a configurable options -I for adjustment.
  tstools_nic_monitor: Write recordings to /storage/packet_captures by default, if the dir exists. Else, /tmp
  tstools_nic_monitor: Feature. Add max iat metric to summary and detailed stats log files, and ! indicator if the max IAT was exceeded.
  tstools_nic_monitor: show indicator flags for IAT and frame not eq 1316 packing issues
  tstools_nic_monitor: show indicator flags for duplicate streams
  tstools_nic_monitor: In summary stats files, don't continiously output data for old and stale streams.
  tstools_nic_monitor: In detailed stats files, don't continiously output data for old and stale streams.
  tstools_nic_monitor: In summary stats files, add the warning indicator flags 'flags=---' summary
  tstools_nic_monitor: In detailed stats files, add the warning indicator flags 'flags=---' summary
  tstools_nic_monitor: In the (debug) json probe-output, add the warning indicator flags 'flags=---' summary
  tstools_nic_monitor: Feature. Added Log View 'L' to track CC stream errors over time (use page up/dn to scroll log)

* Wed Apr 20 2022 Steven Toth <stoth@ltnglobal.com> 
- v1.13.2
  tstools_nic_monitor: Bugfix. Linear memory over-allocation / leak with large number of streams.

* Thu Apr 14 2022 Steven Toth <stoth@ltnglobal.com> 
- v1.13.1
  tstools_stream_verifier: Feature. Modify -o option to support and output URL for live streaming.
  tstools_stream_verifier: Improvements for bitrates above 20mbps. Rated now for 800mbps.
  tstools_nic_monitor: Feature. On the console report, display the start/end time for the stats period.
  tstools_nic_monitor: Known issue. Multiple LTN encoders in MPTS mode, UI reports identical latencies.
  tstools_nic_monitor: Output to console file write interval (and json) interval settings on startup.
  tstools_nic_monitor: Bugfix. nic_monitor: one-time memory leak per stream in the hashing index.
  tstools_nic_monitor: Bugfix. nic_monitor: JSON related cumulative memory leak.
  tstools_nic_monitor: Feature. Significant TR101290 improvements. (Disabled for now)
  tstools_nic_monitor: Add additional fields to the json realtime stats. Load averages and nic name being inspected.
  tstools_asi2ip: New tool. Receive MPEGTS via ASI from Dektec 2172 input port, transmit to IP.
  tstools_scte35_inspector: Feature. Track the related video stream, extract and display PTS.
  tstools_scte35_inspector: Don't parse corrupted sections. (potential crash)
  tstools_scte35_inspector: Slow down calls to avio for better citizen performance.
  tstools_scte35_inspector: Verbose mode 2 now hexdumps TS packet being extracted.

* Mon Jan 10 2022 Steven Toth <stoth@ltnglobal.com> 
- v1.12.0
  tstools_nic_monitor: Bug. Intermittent segfault when resizing window (mostly seen in IAT report mode).
  tstools_nic_monitor: Bug. -w -d console help confusing, correct the description.
  tstools_nic_monitor: Bug. From 1.11, causes file reports to grow rapidly and uncontrolled. Fixed.
  tstools_nic_monitor: Bug. Improvements to -w -d reports so they're fully seperate reports now.
  tstools_nic_monitor: Bug. Fix black rows in the UI if UDP streams are low bitrate or difficult to detect.
  tstools_nic_monitor: Feature. Add a '@Report Begins at <timestamp>' on summary and detailed stats reports, on startup.
  tstools_nic_monitor: Feature. Socket process drop stats now reset to zero, along with other stats, during 'r'
  tstools_nic_monitor: Feature. Add ! indicator in detailed reports per pid, if the value has changed.
  tstools_iat_tester: Add option to randomize packet intervals between 0us and an upper boundary.
  tstools_bitrate_smoother: Add command line example to the console help. (Not production ready)

* Wed Dec  1 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.11.0
  tstools_nic_monitor: Fix unwanted behavior. Prevent -w . or -d . from creating hidden stats files
  tstools_nic_monitor: Bug. socket/report view didn't show bindings to 0.0.0.0:port processes
  tstools_nic_monitor: Feature (disabled). Report PSIP/stats via http/JSON to remote push servers, or UDP, internal dev usage.
  tstools_nielsen_inspector: Feature. Detect Nielsen codes in UDP / Compressed audio stream. (Stereo only MP1/L2- for now).

* Wed Nov 17 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.10.0
  tstools_nic_monitor: Bug: debug bytes appeared on screen during probe phase in UI mode.
  tstools_nic_monitor: Feature - Limited ability to forward an incoming stream to one of three multicast destinations.
  tstools_nic_monitor: Feature - Display processes associated with a UDP stream, and show their socket buffer stats (IPv4 only)
  tstools_nic_monitor: New tool. CBR Bitrate smoother added (NOT CERTIFIED YET, NOT FOR GENERAL USE).
  tstools_nic_monitor: Improvements to support multiple PMTs on a single PID, in model report mode.
  tstools_scte35_inspector: Segfault when processing multipacket SCTE35 table sections.
  
* Tue Aug 31 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.9.0
  tstools_nic_monitor: Add UI support for showing a service information report
  tstools_nic_monitor: In the UI, Show SCTE35 status of the upstream encoder (enabled or not).
  tstools_nic_monitor: In the UI, Show the LTN Encoder version in the UI if it's detected in the stream.
  tstools_nic_monitor: Overhaul the UI menu and add a help page.
  tstools_nic_monitor: Add support for 'lo' loopback interfaces, and any interface even if BROADCAST is not enabled.
  tstools_nic_monitor: Avoid segfault when enumerating network interfaces that don't have an IP address configured.
  tstools_nic_monitor: Add keyboard UI support for switching recordings between PCAP and TS
  tstools_nic_monitor: Add keyboard UI support for switching recordings between segments and single files.
  tstools_nic_monitor: Add LTN Encoder latency reporting to the UI, when it's detected in the stream.
  tstools_nic_monitor: Add stream discovery, bitrate reporting and recording for ATSC3.0 A/324 CTP streams.
  tstools_nic_monitor: Don't attempt to parse random data streams as transport and create lots of console noise.
  tstools_nic_monitor: Add a new stream type "UNK" for streams that don't contain recognizable payload.
  tstools_nic_monitor: Add tool argument to request .TS recordings where possible (vs default being PCAP).
  tstools_nic_monitor: Bug: with MPTS muxes containing program 0, SCTE Registration is being shown.
  tstools_nic_monitor: adjust pcap buffers size upwards to better support 2Gb/ps monitoring.
  tstools_nic_monitor: Indicate the number of input streams in the UI.
  tstools_nic_monitor: Optimize performance for 100x20Mbps (2Gb/ps), increase thread performance significantly.
  tstools_nic_monitor: bugfix related to disappearing cursor at the bottom of the UI list.
  tstools_nic_monitor: Detect and support limited monitoring of SMPTE2110 video, audio and anc streams.
  tstools_scte35_inspector: New tool added to display SCTE35 messages from file or network.
  tstools_ffmpeg_metadata: New tool to extract/view human meaningful metadata from recordings
  tstools_udp_capture: Arg -E added to return a non-zero result code if any CC errors are detected. (harvester)
  tstools_pcap2ts: Add raw mode extraction so that RTP and A/324 streams can also be extracted from pcap files.
  tstools_clock_inspector: Massive performance optimization, 17GB stream analyzed in 3 minutes instead of 2hrs.
  tstools_igmp_join: New tool that issues IGMP joins for specific multicast streams on specific NICS.
  tstools_slicer: New tool that index transport files, can extract MPTS/SPTS segments based on PCR time.
  tstools_slicer: Added support for MPTS and multiple PCR pids, with auto-detection.
  tstools_sei_unregistered: New tool added, search for SEI UNREGISTERED arrays in video files.
  tstools_udp_capture: deprecated. Please switch to using nic_monitor and igmp_join tools.
  tstools_stream_verifier: New tool. Used to generate playout streams with counters, and verify them.
  tstools_pes_inspector: New tool to extract PES objects from transport streams.
  tstools_clock_inspector: Added support for live UDP streams.

* Thu Jun 10 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.8.3
  tstools_udp_capture: Slow down the UI refresh from 25ms to 250ms
  tstools_udp_capture: Bugfix related to high levels of CPU usage and excessive memory growth
  tstools_nic_monitor: UI command H to hide a row, U command unhides all hidden rows.
  tstools_nic_monitor: Ensure recorded files are owned by the calling user, not root.
  tstools_nic_monitor: Console UI option 'I' to show IAT histograms.
  tstools_nic_monitor: Show IAT histograms when the app terminates.
  tstools_nic_monitor: Write IAT histograms to the detailed log files.
  tstools_nic_monitor: Command line option -R to auto record all streams on startup as PCAPS.
  tstools_nic_monitor: Silently abort recordings if the target filesystem is 90% full.
  tstools_nic_monitor: bugfix: stats files were not being created unless operator in UI interactive mode.
  tstools_nic_monitor: Various small leaks and fixes as a result of running valgrind.
  tstools_nic_monitor: Reduced CPU usage when recording 210mb streams.
  tstools_nic_monitor: Improvements to the error reporting if the user passes and bad network interface name.
  tstools_nic_monitor: Append a ! character to the cc error count in stats files, if the stat changes since the last report.
  tstools_nic_monitor: Display a yellow warning in the UI if the recorder I/O backlog is unusually high (busy disk).
  tstools_nic_monitor: Minor man page adjustments
  tstools_pcapts: Tool updates to ease packet interval histogram inspection.
  tstools_pcapts: Bugfix, showing the wrong IP address in -v mode.
  tstools_pcapts: Bugfix, stop and start recordings in UI mode could sometimes lead to partial writes at the end of PCAP file.
  manpage: Added a man page for tstools_pcapts

* Thu Jun 10 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.8.2
  tstools_nic_monitor: In recorded filenames, replace : with .
  tstools_nic_monitor: Using update segmentwriter from libltntstools for file creation.
  tstools_nic_monitor: Render file and segment recording details in the interactive UI.
  tstools_nic_monitor: Add feature to count packets that are not 7 * 188 in length.

* Tue May 18 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.8.1
  tstools_nic_monitor: Memory leak while recording.
  tstools_nic_monitor: One time memory leak when segment_writer (recording) finishes.
  tstools_nic_monitor: Adjusted UI formatting in PID Report mode (wider Packet Count column).
  tstools_nic_monitor: PID Report new feature, count and show when UDP packets are not 7 * 188 long.

* Wed May 12 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.8.0
  tstools_nic_monitor: Record option now creates 1m pcap segment files (use mergecap to join recordings)
  tstools_nic_monitor: Cut/paste improvement. Add a 'freeze' UI command. (Stats continue to be counted silently)
  tstools_nic_monitor: Automatically sort the rows by destination ip:port, rather than random/discovery order.
  tstools_nic_monitor: Moved the current time to lower left.
  tstools_nic_monitor: Put the datetime the tool was started lower right, and update it when a reset occurs.
  tstools_nic_monitor: Change the format that 'PacketCount' is show to include three digit delimiters.
  tstools_nic_monitor: Grow the size of each line by a few characters to accomodate longer packet counters.
  tstools_nic_monitor: Detect duplicate sources sending to the same multicast ip:port and mark as error in UI.
  tstools_nic_monitor: When the tool exits, show the PCAP driver packet dropped stats in the output.
  tstools_nic_monitor: Overhaul pcap recording to better handle high I/O on the platform, reworking internal threads.
  tstools_nic_monitor: Adjusted PCAP buffering again for even higher workloads.
  tstools_nic_monitor: Convert to using the segment writer for recordings.
  tstools_nic_monitor: TR101290 development feature disabled in the menu.
  general: Strip the binary before we make the package.
  udp_capture: Experimental changes (disabled) for a less CPU intensive UDP receiver.
  libltntstools: update segment writer to write an arbitrary file header is segmented mode.

* Fri Jan 29 2021 Steven Toth <stoth@ltnglobal.com> 
- v1.7.0
  tstools_nic_monitor: Support significantly higher bitrates without packet loss in dropped or CC stats.
  tstools_nic_monitor: Support selected stream recording (pcap format) for one or more streams in the UI.
  tstools_nic_monitor: Support selected stream full pid reports in one or more streams in the UI.

* Thu Oct  8 2020 Steven Toth <stoth@ltnglobal.com> 
- v1.6.2
  tstools_nic_monitor: UI changes - show pcap buffer overruns and NIC dropped frames if errors occur.

* Mon Oct  5 2020 Steven Toth <stoth@ltnglobal.com> 
- v1.6.1
  tstools_rtmp_analyzer: Added - tool to detect drifts in stream vs walltime.
  tstools_nic_monitor: Changes to allow libpcap buffer sizes to be adjusted (packet loss in high b/w streams).
  tstools_nic_monitor: Change the bitrate calculator to use a truly high-resolution measurement.
  tstools_udp_capture: Fix an issue with -t where the tool didn't terminate after N seconds.

* Mon Jan  1 2020 Steven Toth <stoth@ltnglobal.com> 
- v1.5.0
  tstools_nic_monitor: Added - detect MPEG-TS packets on unicast addresses.

* Sat Nov  9 2019 Steven Toth <stoth@ltnglobal.com> 
- v1.4.1
  tstools_nic_monitor: Add option -w to create detailed per-pid stats files.

* Mon Jun 17 2019 Steven Toth <stoth@ltnglobal.com> 
- v1.3.1
  udp_capture: Bugfix - random segfault when using -t on shutdown.

* Thu May 30 2019 Steven Toth <stoth@ltnglobal.com> 
- v1.3.0
  udp_capture: Add -t options to stop processing after N seconds.

* Tue May 28 2019 Steven Toth <stoth@ltnglobal.com> 
- v1.2.0
  nic_monitor: Add Inter-Packet-Gap (IPG) measurement. Per TS stream, per-packet latency measurement in ms.
  nic_monitor: Add Inter-Frame-Gap (IFG) measurement. Per PCAP interface, frame latency measurement in ms.

* Tue May 28 2019 Steven Toth <stoth@ltnglobal.com> 
- v1.1.0
  core: Fixes to not rely on libavformat private APIs
  clock_inspector: Improve accuracy of MS measurements. Measure ticks from SCR feature added.
  udp_capture: Add ability to segment the output files.
  udp_capture: Correct a command line usage arg

* Wed May  1 2019 Steven Toth <stoth@ltnglobal.com> 
- v1.0.2
  nic_monitor: man page stats files clarification
  nic_monitor: detect if we're running in sudo then chown stats files ownership accordingly back to the sudo'd uid and gid
  nic_monitor: on error condition, return a more useful error message.
  nic_monitor: Bug: -d should represent an absolue path prefix, not a directory.
  nic_monitor: Avoid compiling the core app many times. Compile onces then link each sub-binary
  build system: Various cleanups related to absolute paths etc.

* Tue Apr 30 2019 Steven Toth <stoth@ltnglobal.com> 
- Initial RPM release
  A handful of tools to record, inspect and analyze mpeg-ts files/streams.

