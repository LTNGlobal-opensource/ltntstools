
AUTOMAKE_OPTIONS = foreign
GIT_VERSION := $(shell git describe --abbrev=8 --dirty --always --tags)

AM_CFLAGS = -Wall -O3 -DVERSION=\"$(VERSION)\" -DPROG="\"$(PACKAGE)\"" -D_FILE_OFFSET_BITS=64 \
	-D_BSD_SOURCE \
	-DKL_USERSPACE -D__STDC_FORMAT_MACROS \
	-DGIT_VERSION=\"$(GIT_VERSION)\"

LDADD = -lpthread -lz -ldl -ldvbpsi -lm

if DEBUG
	CFLAGS += -g
endif

CXXFLAGS = $(CFLAGS)

SRC  = tstools_util.c
SRC += pat_inspector.c
SRC += pmt_inspector.c
SRC += udp.c
SRC += url.c
SRC += udp_capture.c

bin_PROGRAMS  = tstools_util
bin_PROGRAMS += tstools_pat_inspector
bin_PROGRAMS += tstools_pmt_inspector
bin_PROGRAMS += tstools_udp_capture

tstools_util_SOURCES = $(SRC)
tstools_pat_inspector_SOURCES = $(SRC)
tstools_pmt_inspector_SOURCES = $(SRC)
tstools_udp_capture_SOURCES = $(SRC)

libtstools_noinst_includedir = $(includedir)

noinst_HEADERS  = hexdump.h
noinst_HEADERS += version.h
noinst_HEADERS += udp.h
noinst_HEADERS += url.h
noinst_HEADERS += pids.h
