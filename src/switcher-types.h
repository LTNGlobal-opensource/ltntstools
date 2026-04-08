/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

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
#include <sys/types.h>
#include <sys/stat.h>

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"
#include "xorg-list.h"

extern int g_running;

#define MAX_INPUT_STREAMS        16
#define MAX_STREAM_PIDS           2
#define TARGET_BITRATE     20000000 // bps
#define TS_PACKET_SIZE          188
#define TS_PACKETS_PER_SEC (TARGET_BITRATE / (TS_PACKET_SIZE * 8))
#define PACKET_INTERVAL_NS (1000000000 / TS_PACKETS_PER_SEC)
#define MAX_EBN_SIZE 834 * 1000

struct pid_s;
struct stream_s;
struct tool_ctx_s;

enum pid_type_t {
	PID_UNDEFINED,
	PID_VIDEO,
	PID_AUDIO
};

int64_t output_get_computed_stc(struct tool_ctx_s *ctx);

struct pes_item_s
{
	struct xorg_list list;
	struct ltn_pes_packet_s *pes;
	int64_t arrivalSTC; /* local STC clock value when we first got the pes */
	int64_t outputSTC;  /* the local STC clock value when the pes is scheduled for output */
	time_t created;
};

struct pid_s
{
	struct input_stream_s *stream;
	enum pid_type_t type;

	uint16_t pid;
	uint16_t outputPidNr;
	uint8_t streamId;
	void *pe; /* PES Extractor */

	pthread_mutex_t peslistlock;
	uint64_t peslistcount;
	struct xorg_list peslist;

	/* Transport packets to be egressed */
	uint8_t  *pkts;
	uint32_t  pkts_count;
	uint32_t  pkts_idx;
	int64_t  *pkts_outputSTC;
	uint8_t   cc;
	uint8_t   ccRoller;

	struct timespec lastOutputPCR; /* STC ticks */
	uint8_t pkt_scr[188];

	/* Video Buffer Verifier (VBV) */
	void *vbv;
	struct vbv_decoder_profile_s dp;
};

struct input_stream_s
{
	struct tool_ctx_s *ctx;
	int nr;
	char *iname;

	void *avio_ctx;
	struct ltntstools_source_avio_callbacks_s cbs;

	struct ltntstools_stream_statistics_s *libstats;

	int pidCount;
	struct pid_s *pids[MAX_STREAM_PIDS];
};

struct output_stream_s
{
	struct tool_ctx_s *ctx;
	struct ltntstools_reframer_ctx_s *reframer;

	char *oname;
	AVIOContext *avio_ctx;

	int64_t ticks_per_outputts27MHz;

	struct ltntstools_pat_s *pat;

	struct ltntstools_stream_statistics_s *libstats;
};

struct tool_ctx_s
{
	int verbose;
	int inputNr;

	uint8_t null_pkt[188];
	int64_t null_pkt_outputSTC;

	uint8_t psip_cc[3];
	uint8_t psip_pkt[3][188];

	int64_t ts_packets_sent;

	struct timespec next_time;
	struct timespec last_psip;
	struct timespec last_q_report;
	int output_psip_idx;

	/* Streams */
	struct input_stream_s *input_streams[MAX_INPUT_STREAMS];

	struct output_stream_s *outputStream;

	/* Stream scheduling */
	uint32_t schedule_idx;
	int schedule_entries;
	struct pid_s *schedule[4];

};

struct input_stream_s *input_stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr);
struct pid_s *input_pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_t type);
void input_pid_free(struct pid_s *pid);
int input_stream_add_pid(struct input_stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId);
int input_stream_write(struct input_stream_s *stream, struct pid_s *pid, const uint8_t *pkts, int packetCount);
void input_stream_free(struct input_stream_s *stream);
void input_stream_prune_history(struct input_stream_s *is);

struct output_stream_s *output_stream_alloc(struct tool_ctx_s *ctx);
void output_stream_free(struct output_stream_s *os);
int output_write(struct output_stream_s *os, const uint8_t *pkt, int packetCount);
