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

#define MAX_INPUT_STREAMS        16
#define MAX_STREAM_PIDS           2
#define TARGET_BITRATE     40000000 // bps
#define TS_PACKET_SIZE          188
#define TS_PACKETS_PER_SEC (TARGET_BITRATE / (TS_PACKET_SIZE * 8))
#define PACKET_INTERVAL_NS (1000000000 / TS_PACKETS_PER_SEC)
#define MAX_EBN_SIZE 834 * 1000

struct pid_s;
struct stream_s;
struct tool_ctx_s;

extern int g_running;

enum pid_type_t {
	PID_UNDEFINED,
	PID_VIDEO,
	PID_AUDIO
};

struct pes_item_s
{
	struct xorg_list list;
	struct ltn_pes_packet_s *pes;
	int64_t arrivalSTC; /* local STC clock value when we first got the pes */
	int64_t outputSTC;  /* the local STC clock value when the pes is scheduled for output */
};

struct pid_s
{
	struct input_stream_s *stream;	/* A single stream has many pids. Each pids needs to have ES extracted. */
	enum pid_type_t type;

	uint16_t pid;
	uint16_t outputPidNr;		/* Output Pid number we'll generate */
	uint8_t streamId;
	void *pe;					/* PES Extractor per pid. Stack is called back with PEs's extracted from each input*/

	pthread_mutex_t peslistlock;
	uint64_t peslistcount;
	struct xorg_list peslist;

	/* Transport packets to be egressed */
	uint8_t  *pkts;
	uint32_t  pkts_count;
	uint32_t  pkts_idx;
	int64_t  *pkts_outputSTC;
	uint8_t cc;
	uint8_t ccRoller;

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
	char *oname;

	int64_t ticks_per_outputts27MHz;
	
	struct ltntstools_reframer_ctx_s *reframer;
	struct sockaddr_in addr;
	int sockfd;
	int64_t ts_packets_sent;

	struct ltntstools_pat_s *pat;

//	void *avio_ctx;
	//struct ltntstools_stream_statistics_s *libstats;

	int pidCount;
	struct pid_s *pids[MAX_STREAM_PIDS];
};

struct tool_ctx_s
{
	int verbose;
	int inputNr;

	uint8_t null_pkt[188];
	int64_t null_pkt_outputSTC;

	uint8_t psip_cc[3];
	uint8_t psip_pkt[3][188];

	struct timespec next_time;
	struct timespec last_psip;
	struct timespec last_q_report;
	int output_psip_idx;

	/* Streams */
	struct input_stream_s *streams[MAX_INPUT_STREAMS];
	struct output_stream_s *outputStream;

	/* Stream scheduling */
	uint32_t schedule_idx;
	int schedule_entries;
	struct pid_s *schedule[4];

};

/* switcher-core.c */

/* switcher-input.c */
void input_stream_free(struct input_stream_s *stream);
int input_stream_write(struct input_stream_s *stream, struct pid_s *pid, const uint8_t *pkts, int packetCount);
int input_stream_add_pid(struct input_stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId);
struct input_stream_s *input_stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr);

struct pid_s *input_pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_t type);
void input_pid_free(struct pid_s *pid);

/* switcher-output.c */
int output_alloc(struct tool_ctx_s *ctx, struct output_stream_s **outputStream);
void output_free(struct tool_ctx_s *ctx, struct output_stream_s *outputStream);
void *output_reframer_callback(struct tool_ctx_s *ctx, struct output_stream_s *os, const uint8_t *buf, int lengthBytes);
int output_write(struct tool_ctx_s *ctx, struct output_stream_s *outputStream, uint8_t *pkt, int packetCount);
int64_t output_get_computed_stc(struct output_stream_s *os);
