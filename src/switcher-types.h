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

struct pes_item_s;
struct pid_s;
struct input_stream_s;
struct output_stream_s;
struct tool_ctx_s;

enum pid_type_t {
	PID_UNDEFINED,
	PID_VIDEO,
	PID_AUDIO
};

int64_t output_get_computed_stc(struct output_stream_s *os);

struct pes_item_s
{
	struct xorg_list list;
	struct ltn_pes_packet_s *pes; /* Related PES object */
	int64_t arrivalSTC;           /* Local STC clock value when we first got the pes */
	int64_t outputSTC;            /* Local STC clock value when the PES is scheduled for transmission output */
	time_t created;               /* Object creation time in sections. Used for purging. */
};

struct pid_s
{
	struct input_stream_s *stream;   /* parent stream context */
	enum pid_type_t type;            /* Eg. PID_VIDEO, PID_AUDIO */

	uint16_t pid;                    /* Transport PID: 0..8191 */
	uint16_t outputPidNr;            /* Transport PID: 0..8191 */
	uint8_t streamId;                /* PMT PES Stream ID, Eg. 0xc0 audio, 0xe0 video */
	void *pe;                        /* input pidNr PES Extractor */

	pthread_mutex_t peslistlock;     /* protection for list */
	uint64_t peslistcount;           /* Number of items in peslist */
	struct xorg_list peslist;        /* fifo list of PES objects */

	/* Transport packets to be egressed */
	uint8_t  *pkts;                  /* Array of transport packets */
	uint32_t  pkts_count;            /* number of packets in pkts[] */
	uint32_t  pkts_idx;              /* number 0..pkts_count, index into pkts[] array */
	int64_t  *pkts_outputSTC;        /* Array of output clock timestamps, for each packet in pkts[] array */
	uint8_t   cc;                    /* CC creation for output packets */
	uint8_t   ccRoller;              /* Used when correcting any outgoing CCs */

	struct timespec lastOutputPCR;   /* STC ticks. Last time in ticks we output the STC/PCR  */
	uint8_t pkt_scr[188];            /* A fully formed PCR packet */

	/* Video Buffer Verifier (VBV) */
	void *vbv;
	struct vbv_decoder_profile_s dp;
};

struct input_stream_s
{
	struct tool_ctx_s *ctx;  /* parent */
	int nr;                  /* 0..1 */
	char *iname;             /* Eg. udp:/227.1.1.1:4001 */

	void *avio_ctx;          /* AVIO framework context */
	struct ltntstools_source_avio_callbacks_s cbs;    /* Callbacks for our AVIO sources. */
	struct ltntstools_stream_statistics_s *libstats;  /* Transport Stream packet statistics */

	int pidCount;            /* Number of pids in pids[] array */
	struct pid_s *pids[MAX_STREAM_PIDS];
};

struct output_stream_s
{
	struct tool_ctx_s *ctx;   /* parent context */
	struct ltntstools_reframer_ctx_s *reframer; /* TS packets are grouped into 7x188 frames prior to transmission. */

	char *oname;                        /* Output url for transmission. Eg. udp://227.2.2.2:4500 */
	AVIOContext *avio_ctx;              /* ffmpeg output url context. */

	int64_t ticks_per_outputts27MHz;
	int64_t ts_packets_sent;            /* Total number of transport packets transmitted */

	uint8_t null_pkt[188];              /* Holds fully formed null packet */
	int64_t null_pkt_outputSTC;         /* TODO: I don't think we need these timing checks */

	struct ltntstools_pat_s *pat;       /* newly format output PAT/PMT PSIP object, describing entire of transport stream. */

	struct ltntstools_stream_statistics_s *libstats; /* Transport Stream packet statistics */
};

struct tool_ctx_s
{
	int verbose;                     /* -v option increments this higher and higher */
	int inputNr;                     /* */

	int output_psip_idx;             /* Index pointer into psip_pkt[n] */
	uint8_t psip_cc[3];              /* Keeping track of the CC for any PSIP packets */
	uint8_t psip_pkt[3][188];        /* Enough space to hold a PAT in psip_pkt[0], and two single stream PMTs in psip_pkt[1] and psip_pkt[2] */

	struct timespec next_time;       /* Current time */
	struct timespec last_psip;       /* Last time a PSIP TS packet were output */
	struct timespec last_q_report;   /* Last time a PES queue report was dumped to console. */

	/* Streams. Many input, one output. */
	struct input_stream_s *input_streams[MAX_INPUT_STREAMS];
	struct output_stream_s *outputStream;

	/* Stream scheduling */
	uint32_t schedule_idx;           /* Index from 0..schedule_entries, or -1 to indicate inactive. */
	int schedule_entries;            /* Number of pids objects in var schedule[] */
	struct pid_s *schedule[4];       /* Array of pids, we plan to output packets for */
};

struct input_stream_s *input_stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr);
struct pid_s *input_pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_t type);
void input_pid_free(struct pid_s *pid);
int  input_stream_add_pid(struct input_stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId);
int  input_stream_write(struct input_stream_s *stream, struct pid_s *pid, const uint8_t *pkts, int packetCount);
void input_stream_free(struct input_stream_s *stream);
void input_stream_prune_history(struct input_stream_s *is);

struct output_stream_s *output_stream_alloc(struct tool_ctx_s *ctx);
void output_stream_free(struct output_stream_s *os);
int  output_write(struct output_stream_s *os, const uint8_t *pkt, int packetCount);
