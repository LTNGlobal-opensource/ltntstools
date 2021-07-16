
AUTOMAKE_OPTIONS = foreign
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

AM_CFLAGS = -Wall -O3 -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 \
	-D_BSD_SOURCE \
	-DKL_USERSPACE -D__STDC_FORMAT_MACROS \
	-DGIT_VERSION=\"$(GIT_VERSION)\" -g

LDADD = -lpthread -lz -ldl -lm -lltntstools

if LINUX
  LDADD += -lrt
endif

if APPLE
  AM_LDFLAGS := -lavformat -lm -lbz2 -lz -Wl,-framework,CoreFoundation -Wl,-framework,Security
  AM_LDFLAGS += -framework VideoToolbox -framework CoreFoundation -framework CoreVideo -framework CoreMedia
endif

AM_CFLAGS += -I../../target-root/usr/include -g
LDADD += -L../../target-root/usr/lib -ldvbpsi
LDADD += -L../../target-root/usr/lib -lavformat -lavutil -lz -lavcodec -lswresample -lswscale -lavutil -lbz2
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
SRC += pid_drop.c
SRC += nic_monitor.c
SRC += nic_monitor_di.c
SRC += nic_monitor_pcap.c
SRC += parsers.c
SRC += kbhit.c
SRC += rtmp_analyzer.c
SRC += tr101290_analyzer.c
SRC += si_streammodel.c
SRC += utils.c
SRC += iat_tester.c
SRC += ffmpeg_metadata.c

bin_PROGRAMS  = tstools_util
LINKBINS  = tstools_pat_inspector
LINKBINS += tstools_pmt_inspector
LINKBINS += tstools_udp_capture
LINKBINS += tstools_si_inspector
LINKBINS += tstools_pcap2ts
LINKBINS += tstools_clock_inspector
LINKBINS += tstools_pid_drop
LINKBINS += tstools_nic_monitor
LINKBINS += tstools_rtmp_analyzer
LINKBINS += tstools_tr101290_analyzer
LINKBINS += tstools_si_streammodel
LINKBINS += tstools_iat_tester
LINKBINS += tstools_ffmpeg_metadata

tstools_util_SOURCES = $(SRC)

libtstools_noinst_includedir = $(includedir)

noinst_HEADERS  = version.h
noinst_HEADERS += dump.h
noinst_HEADERS += parsers.h
noinst_HEADERS += nic_monitor.h
noinst_HEADERS += utils.h

install-exec-hook:
	$(foreach var,$(LINKBINS),cd $(DESTDIR)$(bindir) && ln -sf tstools_util $(var);)

all-local:
	@$(foreach var,$(LINKBINS),ln -sf tstools_util $(var);)

clean-local:
	@$(foreach var,$(LINKBINS),rm -f $(var);)

# OSX codesigning notes.
# codesign --force --deep -s "Developer ID Application: LTN" tstools_util
# codesign --verify --verbose tstools_util
# spctl -a -v tstools_util
