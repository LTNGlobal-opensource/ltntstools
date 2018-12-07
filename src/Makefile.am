
AUTOMAKE_OPTIONS = foreign
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

AM_CFLAGS = -Wall -O3 -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 \
	-D_BSD_SOURCE \
	-DKL_USERSPACE -D__STDC_FORMAT_MACROS \
	-DGIT_VERSION=\"$(GIT_VERSION)\"

LDADD = -lpthread -lz -ldl -lm
AM_CFLAGS += -I../../ltntstools-ffmpeg/root/include
AM_CFLAGS += -I../../ltntstools-libdvbpsi/root/include
LDADD += -L../../ltntstools-libdvbpsi/root/lib -ldvbpsi
LDADD += -L../../ltntstools-ffmpeg/root/lib -lavformat -lavutil -lz -lavcodec -lswresample -lswscale -lavutil
LDADD += -lpcap

#ifdef __APPLE__
#LDADD += -liconv
#endif

if DEBUG
	CFLAGS += -g
endif

CXXFLAGS = $(CFLAGS)

SRC  = tstools_util.c
SRC += pat_inspector.c
SRC += pmt_inspector.c
SRC += dump.c
SRC += udp_capture.c
SRC += si_inspector.c
SRC += pcap2ts.c
SRC += clock_inspector.c
SRC += pes.c
SRC += pids.c
SRC += ts.c
SRC += pid_drop.c
SRC += nic_monitor.c

bin_PROGRAMS  = tstools_util
bin_PROGRAMS += tstools_pat_inspector
bin_PROGRAMS += tstools_pmt_inspector
bin_PROGRAMS += tstools_udp_capture
bin_PROGRAMS += tstools_si_inspector
bin_PROGRAMS += tstools_pcap2ts
bin_PROGRAMS += tstools_clock_inspector
bin_PROGRAMS += tstools_pid_drop
bin_PROGRAMS += tstools_nic_monitor

tstools_util_SOURCES = $(SRC)
tstools_pat_inspector_SOURCES = $(SRC)
tstools_pmt_inspector_SOURCES = $(SRC)
tstools_udp_capture_SOURCES = $(SRC)
tstools_si_inspector_SOURCES = $(SRC)
tstools_pcap2ts_SOURCES = $(SRC)
tstools_clock_inspector_SOURCES = $(SRC)
tstools_pid_drop_SOURCES = $(SRC)
tstools_nic_monitor_SOURCES = $(SRC)

libtstools_noinst_includedir = $(includedir)

noinst_HEADERS  = hexdump.h
noinst_HEADERS += version.h
noinst_HEADERS += pids.h
noinst_HEADERS += dump.h
noinst_HEADERS += histogram.h
noinst_HEADERS += pes.h
noinst_HEADERS += ts.h
