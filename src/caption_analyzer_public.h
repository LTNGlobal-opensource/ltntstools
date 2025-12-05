/* Copyright LiveTimeNet, Inc. 2025. All Rights Reserved. */

#ifndef CAPTION_ANALYZER_PUBLIC_H
#define CAPTION_ANALYZER_PUBLIC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include <libltntstools/ltntstools.h>
#include <libklscte35/scte35.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"
#include "source-pcap.h"
#include "codecs.h"

#include "libzvbi.h"
#include "langdict.h"

#define TELETEXT_DISPLAYSIZE 8192
#define PROMETHEUS_EXPORTER_PORT 0
	
enum pid_type_e {
	PT_UNKNOWN = 0,
	PT_OP47,
	PT_VIDEO,
};

struct prometheus_exporter_s
{
	int serverfd;
	int inputPort;
};

struct input_pid_s
{
	struct tool_ctx_s *ctx;

	int enabled;                   /* Pid active. Boolean */
	enum pid_type_e payloadType;   /* PT_OP47, PT_VIDEO etc */
	uint16_t pid;                  /* Max 0x1fff */
	uint16_t streamId;             /* Pes Extractor StreamID 0xC0, 0xE0 etc */
	uint16_t ttx_page;             /* Teletext subtitle page, typically 888 */
	char ttx_lang[4];              /* Eg. eng */
	uint16_t programNumber;        /* MPEGTS stream program number */

	void *pe;                      /* PesExtractor Context */

	vbi_decoder *decoder;          /* zvbi decoder */
	vbi_page page;                 /* zvbi decoder */
	char *display;                 /* Buffer to contact decoded caption/subtitle ASCII */

	void *langdict_ctx;            /* Dictionary context */

	uint64_t syntaxError;          /* Count of number of syntax errors we're detecting for this stream */

	struct langdict_stats_s stats[LANG_MAX_DEFINED];
};

struct tool_ctx_s
{
	int verbose;

	void *src_pcap;            /* Source-pcap context */
	char *iname;
	char *pcap_filter;

	uint64_t callbackCounter;

	void *sm;                  /* StreamModel Context */
	int smcomplete;            /* Is the streamModel complete and ready for access? Bool. */
	int isMPTS;                /* Bool */

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;                  /* AVIO or PCAP */
	int isRTP;                 /* Bool */

#define MAX_PIDS 0x2000
	struct input_pid_s pids[MAX_PIDS];

	int totalOrderedPids;     /* Number of active pids in the ordered list */
	struct input_pid_s *pidsOrdered[MAX_PIDS];

	struct prometheus_exporter_s prom_ctx;
};

char *strcasestr(const char *haystack, const char *needle);
int langdict_sort_dict(enum langdict_type_e langtype);

int  caption_analyzer_metrics_alloc(struct prometheus_exporter_s *prom_ctx);
void caption_analyzer_metrics_free(struct prometheus_exporter_s *prom_ctx);
void caption_analyzer_metrics_service(struct prometheus_exporter_s *prom_ctx);

#endif /* CAPTION_ANALYZER_PUBLIC_H */
