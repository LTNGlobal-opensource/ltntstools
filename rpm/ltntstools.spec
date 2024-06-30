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
/usr/local/bin/tstools_srt_transmit
/usr/local/bin/tstools_ntt_inspector
/usr/local/bin/tstools_sei_latency_inspector
/usr/local/share/man/man8/tstools_pcapts.8
/usr/local/share/man/man8/tstools_ffmpeg_metadata.8


%changelog
* Wed Feb  7 2024 Steven Toth <steven.toth@ltnglobal.com> 
- v1.31.0 dev release
  tstools_nic_monitor: bugfix. Curl http post mechanism would leak sockets

* Wed Feb  7 2024 Steven Toth <steven.toth@ltnglobal.com> 
- v1.30.0
  tstools_si_inspector: Support for decoding and showing Teletext/WST PMT stream descriptors
  tstools_si_inspector: Print correct stream type for JPEG-XS
  libltntstools: stats improvements for how we measure pcr walltime, new API to retieive last drift measurement.
  libltntstools: stats improvements - PCR jitter histogram now makes it clear the value is absolute
  tstools_clock_inspector: Added support to calculate (for live streams) SCR vs walltime drift (ms)
  tstools_clock_inspector: Added support to calculate (for live streams) PTS vs walltime drift (ms)
  tstools_clock_inspector: Adjusted SCR column headers for easier reading.
  tstools_nic_monitor: Added measure-scheduling-stalls feature to check scheduler performance on questionable servers.
  codebase: compiler redefined UDP header source, lots of tools needed structure field name references adjusted.

* Tue Feb  6 2024 Steven Toth <steven.toth@ltnglobal.com> 
- v1.29.0
  tstools_clock_inspector: Output console help when no args are specified
  tstools_clock_inspector: Output console examples of commands
  tstools_clock_inspector: Output seconds and ms of walltime on each SCR report to console.
  tstools_clock_inspector: Output to console kernel socket buffer sizes on startup.
  tstools_clock_inspector: Memory usage continually grows when when -R (time ordered lists) isn't required.
  tstools_clock_inspector: Change error warning on commandline when -i is used, to be more helpful.
  tstools_clock_inspector: Adjust SCR report header to tidy up whitespace.
  tstools_clock_inspector: Adjust SCR report line for file hexposition to support 9 digits
  tstools_sei_latency_inspector: Added support for PCAP inputs.
  tstools_pes_inspector: Changed typo in command line help from H.266 to H.265
  tstools_pes_inspector: Added -F option to write H.265 NALS to disk
  tstools_nic_monitor: Segfault on shutdown, use after free relating to the object hash/cache.
  tstools_nic_monitor: Bugfix with -i option when using ts file input. non 7*188 frames were discarded and created errors.
  tstools_nic_monitor: Histogram (right side) percentages after reset were inaccurate
  tstools_bitrate_smoother: Disabled RTP processing short term - to work around an Ops performance issue.
  tstools_bitrate_smoother: Segfault when terminating tool if no input packets were received.
  tstools_bitrate_smoother: Added option to drop one or more pids via -R

* Mon Oct 16 2023 Steven Toth <steven.toth@ltnglobal.com> 
- v1.28.0
  tstools_clock_inspector: Show SCR/PCR time in friendly ascii format on SCR lines.
  tstools_clock_inspector: Add -t arg to stop tool after N seconds.
  tstools_sei_unregistered: Add support to -c option to find HEVC SEI caption sequences.
  tstools_sei_unregistered: buffer search adjustment
  tstools_nielsen_decoder: Failed to startup, error "unable to add audio stream"
  tstools_nic_monitor: Automatically reset all stats after startup.
  tstools_sei_latency_inspector: Experimental tool to calculate video processing latency between sampling points.
  tstools_nic_monitor: segfault with extreme low bitrate non video streams, when using 'multicast' filter.

* Mon Apr 24 2023 Steven Toth <steven.toth@ltnglobal.com> 
- v1.27.0
  tstools_bitrate_smoother: Add support for RTP stream smoothing.
  tstools_nic_monitor: Ensure the pcap callback is not batched every 200ms. (Only occurs on later libpcap/Ubuntu releases)
  tstools_ntt_inspector: Leverages/inherits adjusted pcap immediate mode latency.
  tstools_scte35_inspector: Leverages/inherits adjusted pcap immediate mode latency.
  tstools_smpte2038_inspector: Leverages/inherits adjusted pcap immediate mode latency.
  libltntstools library: Ensure the pcap callback is not batched every 200ms. (Only occurs on later libpcap/Ubuntu releases)
  libltntstools library: Added experimeental smoother-rtp framework.

* Wed Apr 19 2023 Steven Toth <steven.toth@ltnglobal.com> 
- v1.26.1
  tstools_nic_monitor: Attempt to detect significant sub second bitrate bursting. Calculate bitrates at 100 and 10ms intervals.
  tstools_nic_monitor: In UI IAT report mode, show the highest bitrate measured for 100ms and 10ms bins (projected into a 1second value)
  tstools_nic_monitor: In stats file logging mode, log the highest bitrate measured for 100ms and 10ms bins (projected into a 1second value)
  tstools_nic_monitor: In stats file logging mode, change the label iat= to iat1000=
  tstools_nic_monitor: In UI help menu, change help text related to stream selection controls.
  tstools_nic_monitor: In Model report, add decimal pids to UI view.
  tstools_nic_monitor: In UI mode with audio lang descriptors, avoid iso639 buffer overflow.
  tstools_pid_drop: Removed counter options. Added 0x2000 Add/Remove options. Overall simplifications.
  tstools_pid_drop: Added examples to console usage/help.
  tstools_scte35_inspector: Assert/abort during parsing of specific NBA streams.
  tstools_scte35_inspector: Free up on exit a one-time small memory allocation (valgrind)
  libltntstools library: throughput_hires: Taking more CPU time than necessary when calculating precise timing measurements.
  libltntstools library: pes-extractor: Avoid Assert/segfault, don't parse pes frames less than 8 bytes.

* Mon Mar  6 2023 Steven Toth <steven.toth@ltnglobal.com> 
- v1.25.0
  tstools_si_inspector: In -v mode, output the per-audio stream language descriptors.
  tstools_nic_monitor: In Model report, show the detected audio language and type if present.

* Thu Feb 23 2023 Steven Toth <steven.toth@ltnglobal.com> 
- v1.24.0
  tstools_bitrate_smoother: When report CC errors, be clear if its input or output related
  tstools_bitrate_smoother: LOS terminate didn't happen in all cases, found during testing.
  libltntstools library: smoother_pcr: Poor IATs occured after 26.5hrs of runtime.
  libltntstools library: smoother_pcr: Slow underrun and exhaustion of latency buffer
  libltntstools library: smoother_pcr: Exhausted the latency buffer due to poor time scheduling in extended runtimes.

* Thu Feb  2 2023 Steven Toth <steven.toth@ltnglobal.com> 
- v1.23.0
  tstools_bitrate_smoother: Fixed segfault on exit, use after free.
  libltntstools library: smoother_pcr: Leaking pcr objects slowly over time.
  libltntstools library: smoother_pcr: Bug during PCR significant changes, leaking to output stalls, high CPU and memory growth.
  libltntstools library: smoother_pcr: Gracefully hand the case where the PCR shifts by more than 15 seconds in either direction.

* Fri Jan  6 2023 Steven Toth <steven.toth@ltnglobal.com> 
- v1.22.0
  tstools_nic_monitor: Changed all use of library pid stats use from a static to dynamic allocations.
  tstools_nic_monitor: Opt in new feature (measure-sei-latency-always), measure latency through a websockets/Arc relay.
  tstools_nic_monitor: Adjust developer option to show a new struct size
  tstools_nic_monitor: Additional ptr safety checks around mallocs (we were having random segfaults)
  tstools_nic_monitor: Move rtp analyzer initialization into RTP specific processing, reduces overall memory usage by 2.5MB
  tstools_nic_monitor: Reduce per stream memory usage by 7MB with better stats caching.
  tstools_nic_monitor: Adjust on-screen help options. 
  tstools_nic_monitor: Implement Clock reporting. Measures PCR intervals and jitter.
  tstools_nic_monitor: Added report-memory-usage option, disabled by default
  tstools_nic_monitor: Show Rx and Tx bitrate totals in the interactive UI
  tstools_nic_monitor: rtp-analyzer: formatting issue related to massive timestamps fixed
  tstools_bitrate_smoother: Changed all use of library pid stats use from a static to dynamic allocations.
  tstools_nielsen_inspector: Bugfix: Compile time issue preventing ALL audio code detection.
  tstools_nielsen_inspector: Raise a sensible error and exit, if the SDK isn't found during runtime.
  tstools_scte35_inspector: During trigger reporting, show the last video pts time in a human readable time format.
  tstools_scte35_inspector: Don't hang after analyzing a file, recognize end of file and terminate cleanly.
  tstools_smpte2038_inspector: Don't hang after analyzing a file, recognize end of file and terminate cleanly.
  tstools_pes_inspector: Don't hang after analyzing a file, recognize end of file and terminate cleanly.
  tstools_clock_inspector: Only report 'processing' percentage if the input is a file.
  general: Slight adjustment to the tool launch process, tstools_bitrate_smoother1..X are valid binaries.
  libltntstools library: rtpanalyzer: avoid freeing a histogram if it wasn't previously allocated
  libltntstools library: stats: add pcr interval and jitter measurements for any detected PCRs
  libltntstools library: adjusting stats framework to issue alloc/free/clone methods (making space for new functionality)

* Tue Nov 22 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.21.0
  tstools_nic_monitor: Bugfix. Segfault on exit, if you didn't specify -F for a custom filter. Safe, but annoying.
  tstools_nic_monitor: Added some basic RTP header analysis with console reporting.
  tstools_nic_monitor: Added option --report-rtp-headers to report RTP headers to console.
  tstools_nic_monitor: Removed HTTP Push from --http-json-reporting option, removed need for curl and shared dep libs complexity.

* Mon Nov 14 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.20.0
  tstools_nic_monitor: Don't show a bogus PCR measurement in Model View for program number zero.
  tstools_nic_monitor: Avoid SRT buffer warnings with high jitter and bursty streams
  tstools_nic_monitor: Display SDT Service name / provider if available in the model view.
  tstools_nic_monitor: Fix a one-time 46byte leak on shutdown.
  tstools_nic_monitor: Fix a memory caching issue introduced in v1.17. Extended use would exhaust system ram.
  tstools_igmp_join: Overhaul tool, reduced cpu usage and support up to 64 joins on a single nic.

* Thu Nov  2 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.19.0
  tstools_bitrate_smoother: Adjust console help example command, remove -b and replace with -l.
  tstools_bitrate_smoother: Feature. Add option -L to terminate process after N seconds of input LOS.
  tstools_bitrate_smoother: Report system socket buffer sizes on the console.
  tstools_bitrate_smoother: Feature. Discover PCR pid automatically.
  tstools_bitrate_smoother: Show dates/times in log messages for important events.

* Thu Oct 13 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.18.0
  tstools_si_inspector: When dumping descriptors, add decoding for AVC_Video_Descritor type.
  tstools_si_inspector: Reflect the fact we support RTP in the online help.
  tstools_smpte2038_inspector: Bigfux. Fixup CTRL-C termination issue.
  tstools_smpte2038_inspector: Added support for RTP/ source-avio input.
  tstools_scte35_inspector: Reflect the fact we support RTP in the online help.
  tstools_si_streammodel: Reflect the fact we support RTP in the online help.
  tstools_pes_inspector: Reflect the fact we support RTP in the online help.
  tstools_pat_inspector: Add RTP support. General code tidy up. Updated online help.
  tstools_pmt_inspector: Add RTP and stream support. Overhaul / tidy up and better online help.
  tstools_sei_unregistered: Add RTP support, migrate to the source-avio framework.
  tstools_nielsen_inpector: Add RTP support, migrate to the source-avio framework.
  tstools_ntt_inspector: Fixes for printing status line in pcap mode and flushing stdout
  
* Thu Oct 13 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.17.0
  tstools_nic_monitor: Update console help to show correct recording locations.
  tstools_nic_monitor: Feature. Add --show-h264-metadata open to show more advanced H264 codec statistics (experimental - opt in).
  tstools_nic_monitor: Man page removed
  tstools_nic_monitor: UI Log. Remove leading space before : seperator in log messages, and allow log lines greater than 80 chars
  tstools_nic_monitor: Initialize internal log document before we initialize TR101290 (future feature)
  tstools_nic_monitor: When TR101290 is enabled (future), place all messages into the UI log (L key) for user view
  tstools_nic_monitor: Feature: Added --http-json-reporting feature to http post json stats to a remote server (Experimental)
  tstools_nic_monitor: Adding libcurl / libjsonc as deps. All are present on centos7 and almalinux 8.4
  tstools_nic_monitor: Improvements in --show-h264-metadata mode when showing H264 codec information for main profile codecs.
  tstools_slicer: Update the console help, the description for -l -s -e were missing.
  tstools_smpte2038_inspector: bugfix in libklvanc dependency, 2038 parsing crash with test case MEM_ATL.
  tstools_smpte2038_inspector: In auto-detect pid mode, if we don't detect a pid, terminate with a NO PID found hekpful message.
  tstools_smpte2038_inspector: Support proper terminate if the user initiates CTRL-C
  tstools_smpte2038_inspector: minor console help verbage cleanup
  tstools_pes_inspector: Add support -E to record H.264 nals to individual files for offline analysis.
  tstools_pes_inspector: Add support -T to produce fullsize h264 thumbnail jpegs every 5 seconds. (disabled in production builds)
  tstools_pes_inspector: Improve -T support to also produce 160x90 thumbnails (disabled in production builds)
  tstools_pes_inspector: Switch to source-avio frame for better RTP handling.
  tstools_si_streammodel: Switch to source-avio frame for better RTP handling.
  tstools_scte35_inspector: Bugfix. Segfault on exit when no SCTE35 detected in stream.
  tstools_scte35_inspector: Bugfix. Misdetected RTP inputs.
  tstools_si_inspector: Bugfix. Misdetected RTP inputs.
  tstools_ntt_inspector: New tool added, to help monitor NBA tissot data in SMPTE2038 streams.
  tstools_ntt_inspector: minor console help verbage cleanup
  tstools_nielsen_inpector: Fix new compiler warning comparison between signed and unsigned integer expressions
  tstools_asi2ip: Fix compiler new compiler warnings re set but unused vars
  tstools_ffmpeg_metadata: Fix new compiler warning re signed vs unused usage. Removed unused signal handler

%changelog
* Thu Sep  1 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.16.0
  tstools_nic_monitor: Feature. Added support for an SRT input urls, monitor an SRT feed. -i srt://1.2.3.4:5678
  tstools_nic_monitor: Add LTN Encoder latency measurement (in ms) to -d -w log files, or 'n/a' when not detected.
  tstools_nic_monitor: Adjust -d -w logfiles to report maxIAT for the last -n seconds, instead of the max IAT since the stats were reset.
  tstools_nic_monitor: Moved 6-7 developer console messages (settings) into -v verbose mode, if people still need them.
  tstools_nic_monitor: Bug. Attempting to record from FILE or SRT input would not create a recording.
  tstools_nic_monitor: Missing enclat "n/a" value in stats files, when non-ltn encoder detected.
  tstools_pes_inspector: Add support -4 for measuring H.264/AVC per-NAL bitrate throughput for live streams.
  tstools_pes_inspector: Add support -5 for measuring H.265/HEVC per-NAL bitrate throughput for live streams.
  tstools_pes_inspector: In H265 NAL bitrate measure mode, change a Padding NAL console description to be more helpful.
  tstools_scte35_inspector: If a trigger fails to parse, report the issue instead of ignoring it.
  tstools_pid_drop: Add support for multiple concurrent pids to be dropped.
  tstools_clock_inspector: Removed a spurious break during command processing, no impact to users.
  tstools_stream_verifier: Switch from custom reframer to common library code
  tstools_bitrate_smoother: Switch from custom reframer to common library code
  tstools_bitrate_smoother: Known issue. Upstream packet loss disrupts processing, process has to be restarted.

* Mon Aug  8 2022 Steven Toth <steven.toth@ltnglobal.com> 
- v1.15.1
  tstools_udp_capture: Tool removed. Deprecated in v1.9.0. See tstools_igmp_join if you need IGMP tooling. 
  tstools_nic_monitor: The default location for all tr101290 logs is /storage/ltn/log, or /tmp if it doesn't exist, or a user override.
  tstools_nic_monitor: Feature. Adjust -i option to analyze in realtime transport files from disk.
  tstools_nic_monitor: Refactored the way we processing command line args to make room for future needs.
  tstools_nic_monitor: Make the UDP port forwarding addresses configurable, see --udp-forwarder in help.
  tstools_nic_monitor: Changed -O option to explicit --danger-skip-freespace-check option.
  tstools_nic_monitor: Fixed broken -1 option. Replaced with new syntax, see --measure-scheduling-quanta.
  tstools_nic_monitor: Removed an unhelpful 'Stream PMT didn't arrive X vs Y messages, mostly seen in freeze UI mode.
  tstools_nic_monitor: Show the D.HH:MM:SS.ms PCR in the model report. (Takes a few seconds to appear).
  tstools_nic_monitor: Bugfix, -D prefix not working and allowing arbitrary file prefixes.
  tstools_nic_monitor: Feature. Add SMPTE2038 registration description Yes / No when detected in Model UI.
  tstools_srt_transmit: Feature. Playout SPTS/MPTS MPEG-TS files from disk in realtime to a SRT receiver.
  tstools_smpte2038_inspector: Output helpful message and stream service information if the smpte2038 pid isn't found.
  tstools_smpte2038_inspector: Improvements related to EVERTZ XPS SMPTE2038 detection.
  tstools_igmp_join: Removed some unused context vars (code tidy up).
  tstools_bitrate_smoother: Removed hard output bitrate arg requirement, using jitter protection latency (ms) instead.
  tstools_bitrate_smoother: Adjust help description for latency, show default value (in ms).
  tstools_bitrate_smoother: Adjust verbose features. Add mode to show current stream PCR times in human readible formats.
  tstools_bitrate_smoother: Ensure output UDP frames are always 1316 in length.
  tstools_sei_unregistered: Add support -c for searching for H.264 SEI Caption headers
  tstools_sei_unregistered: Add support -f for searching for H.264 SEI Filler Padding headers
  tstools_sei_unregistered: Add support -P for dumping all NAL types (including padding)
  tstools_pes_inspector: Add support -4 for measuring H.264 per-NAL throughput for live streams.
  tstools_si_inspector: Add optional debug when verbose levels raised.

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

