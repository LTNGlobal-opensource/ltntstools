
AUTOMAKE_OPTIONS = foreign
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

if LINUX
if BUILD_SHARED
AM_LDFLAGS  = -Wl,-rpath='$$ORIGIN/../lib-ltntstools' -Wl,-z,origin
AM_LDFLAGS += $(shell pkg-config --libs srt libltntstools json-c libklscte35 zvbi-0.2 libklvanc)
AM_LDFLAGS += $(shell pkg-config --libs libavformat libavutil libavcodec libswresample libswscale)
AM_LDFLAGS += $(shell pkg-config --libs libcurl)
endif
endif

AM_CFLAGS = -Wall -O3 -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 \
	-D_DEFAULT_SOURCE \
	-DGIT_VERSION=\"$(GIT_VERSION)\" \
	-I../../ffmpeg/libavcodec \
	-I../../ffmpeg -Wsign-compare

LDADD = -lpthread -lz -lm -lltntstools -lklvanc -lzvbi

if LINUX
  LDADD += -lrt
endif

if APPLE
  AM_LDFLAGS := -lavformat -lm -lbz2 -lz -Wl,-framework,CoreFoundation -Wl,-framework,Security
  AM_LDFLAGS += -framework VideoToolbox -framework CoreFoundation -framework CoreVideo -framework CoreMedia
endif

AM_CFLAGS += -I../../target-root/usr/include -g
if APPLE
AM_CFLAGS += ../../target-root/usr/lib/libjson-c.a
endif
LDADD += -L../../target-root/usr/lib -ldvbpsi
LDADD += -L../../target-root/usr/lib -lavformat -lavutil -lz -lavcodec -lswresample -lswscale -lavutil -lbz2
LDADD += -lpcap -llzma
LDADD += -lklscte35 -ldl
LDADD += -lsrt -lcrypto
if LINUX
if DTAPI
LDADD += ../../sdk-dektec/LinuxSDK/DTAPI/Lib/GCC4.8_CXX11_ABI0/DTAPI64.o
endif
#LDADD += -lmediainfo
#LDADD += -lcurl
if BUILD_STATIC
LDADD += ../../target-root/usr/lib/libjson-c.a
endif
#LDADD += -lrdkafka
endif
if NTT
LDADD += -lntt
endif

#ifdef __APPLE__
#LDADD += -liconv
#endif

if DEBUG
	CFLAGS += -g
endif

AM_CXXFLAGS = $(AM_CFLAGS) -D__STDC_FORMAT_MACROS -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -std=c++11

SRC  = tstools_util.c
SRC += pat_inspector.c
SRC += pmt_inspector.c
SRC += dump.c
SRC += base64.c
SRC += si_inspector.c
SRC += pcap2ts.c
SRC += clock_inspector.c
SRC += clock_inspector_ts.c
SRC += clock_inspector_misc.c
SRC += clock_inspector_pcr.c
SRC += clock_inspector_pes.c
SRC += pid_drop.c
SRC += nic_monitor.c
SRC += nic_monitor_di.c
SRC += nic_monitor_pcap.c
SRC += nic_monitor_json.c
SRC += nic_monitor_tr101290.c
SRC += nic_monitor_kafka.c
SRC += parsers.c
SRC += kbhit.c
SRC += rtmp_analyzer.c
SRC += tr101290_analyzer.c
SRC += si_streammodel.c
SRC += scte35_inspector.c
SRC += utils.c
SRC += iat_tester.c
SRC += ffmpeg_metadata.cpp
SRC += igmp_join.c
SRC += slicer.c
SRC += hash_index.c
SRC += sei_unregistered.c
SRC += stream_verifier.c
SRC += pes_inspector.c
SRC += bitrate_smoother.c
SRC += nielsen_inspector.cpp
if DTAPI
SRC += asi2ip.cpp
endif
#SRC += media.cpp
SRC += smpte2038_inspector.cpp
SRC += srt_transmit.c
SRC += source-avio.c
if NTT
SRC += ntt_inspector.cpp
endif
SRC += sei_latency_inspector.c
SRC += kl-lineartrend.c
SRC += caption_analyzer.c
SRC += caption_analyzer_metrics.c
SRC += langdict.c
SRC += nal_h264.c
SRC += nal_h265.c
SRC += h264_codec_metadata.c
SRC += h265_codec_metadata.c
SRC += audioanalyzer.c
SRC += nielsen-bindings.cpp
SRC += golomb.c
SRC += source-rcts.c

bin_PROGRAMS  = tstools_util
LINKBINS  = tstools_pat_inspector
LINKBINS += tstools_pmt_inspector
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
LINKBINS += tstools_scte35_inspector
LINKBINS += tstools_igmp_join
LINKBINS += tstools_slicer
LINKBINS += tstools_sei_unregistered
LINKBINS += tstools_stream_verifier
LINKBINS += tstools_pes_inspector
LINKBINS += tstools_bitrate_smoother
LINKBINS += tstools_nielsen_inspector
if DTAPI
LINKBINS += tstools_asi2ip
endif
LINKBINS += tstools_smpte2038_inspector
LINKBINS += tstools_srt_transmit
if NTT
LINKBINS += tstools_ntt_inspector
endif
LINKBINS += tstools_sei_latency_inspector
LINKBINS += tstools_caption_analyzer

tstools_util_SOURCES = $(SRC)

libtstools_noinst_includedir = $(includedir)

noinst_HEADERS  = version.h
noinst_HEADERS += dump.h
noinst_HEADERS += parsers.h
noinst_HEADERS += nic_monitor.h
noinst_HEADERS += utils.h
noinst_HEADERS += hash_index.h
noinst_HEADERS += source-avio.h
noinst_HEADERS += kl-lineartrend.h
noinst_HEADERS += langdict.h
noinst_HEADERS += caption_analyzer_public.h
noinst_HEADERS += clock_inspector_public.h
noinst_HEADERS += nal_h264.h
noinst_HEADERS += nal_h265.h
noinst_HEADERS += h264_codec_metadata.h
noinst_HEADERS += h265_codec_metadata.h
noinst_HEADERS += audioanalyzer.h
noinst_HEADERS += nielsen-bindings.h
noinst_HEADERS += source-rcts.h

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
