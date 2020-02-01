
AUTOMAKE_OPTIONS = foreign
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

AM_CFLAGS = -Wall -O3 -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 \
	-D_BSD_SOURCE \
	-DKL_USERSPACE -D__STDC_FORMAT_MACROS \
	-DGIT_VERSION=\"$(GIT_VERSION)\"

LDADD = -lpthread -lz -ldl -lm

if LINUX
  LDADD += -lrt
endif

if APPLE
  AM_LDFLAGS := -lavformat -lm -lbz2 -lz -Wl,-framework,CoreFoundation -Wl,-framework,Security
  AM_LDFLAGS += -framework VideoToolbox -framework CoreFoundation -framework CoreVideo -framework CoreMedia
endif

AM_CFLAGS += -I../../target-root/usr/include
LDADD += -L../../target-root/usr/lib -ldvbpsi
LDADD += -L../../target-root/usr/lib -lavformat -lavutil -lz -lavcodec -lswresample -lswscale -lavutil
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
SRC += parsers.c
SRC += kbhit.c

bin_PROGRAMS  = tstools_util
LINKBINS  = tstools_pat_inspector
LINKBINS += tstools_pmt_inspector
LINKBINS += tstools_udp_capture
LINKBINS += tstools_si_inspector
LINKBINS += tstools_pcap2ts
LINKBINS += tstools_clock_inspector
LINKBINS += tstools_pid_drop
LINKBINS += tstools_nic_monitor

tstools_util_SOURCES = $(SRC)

libtstools_noinst_includedir = $(includedir)

noinst_HEADERS  = hexdump.h
noinst_HEADERS += version.h
noinst_HEADERS += pids.h
noinst_HEADERS += dump.h
noinst_HEADERS += histogram.h
noinst_HEADERS += pes.h
noinst_HEADERS += ts.h
noinst_HEADERS += parsers.h

install-exec-hook:
	$(foreach var,$(LINKBINS),cd $(DESTDIR)$(bindir) && ln -sf tstools_util $(var);)

all-local:
	@$(foreach var,$(LINKBINS),ln -sf tstools_util $(var);)

clean-local:
	@$(foreach var,$(LINKBINS),rm -f $(var);)

