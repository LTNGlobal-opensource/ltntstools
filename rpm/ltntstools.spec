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
/usr/local/share/man/man8/tstools_nic_monitor.8

%changelog
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

