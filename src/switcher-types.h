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

enum pid_type_e {
	PID_UNDEFINED,
	PID_VIDEO,
	PID_AUDIO,
	PID_OTHER,
};

enum SliceType_e {
	SLICE_UNDEFINED = 0,
	SLICE_I, SLICE_B, SLICE_P
};

enum pid_state_e {
	PS_UNDEFINED = 0,
	PS_SCHEDULE_NO_OP,         /* When schedule for a packet, return no packet regardless if something is available */
	PS_SCHEDULE_NEXT_PACKET,   /* When schedule for a packet, do an actual packet from the TS queue. */  
	PS_SCHEDULE_EOL,           /* pid at end of list, mot ts packets required. */
};

struct timing_item_s			/* We cache any clocks per PID, so there are derised from struct ltn_pes_packet_s objects. */
{
	struct   xorg_list list;
	uint32_t PTS_DTS_flags;		/* ISO13818-1 Table 2-17. bitmask. bit 1 = PTS is present. Bit 0 = DTS is present. */
	int64_t  PTS;				/* taken from struct ltn_pes_packet_s object */
	int64_t  DTS;				/* taken from struct ltn_pes_packet_s object */
	int64_t  arrivalSTC;		/* taken from struct pes_item_s object */
	int64_t  outputSTC;			/* taken from struct pes_item_s object */
	time_t   created;           /* Object creation time in seconds. Used for purging. */
};

struct pes_item_s
{
	struct xorg_list list;
	struct ltn_pes_packet_s *pes; /* Related PES object */
	struct pid_s *pid;            /* parent */
	int64_t arrivalSTC;           /* Local STC clock value when we first got the pes */
	int64_t outputSTC;            /* Local STC clock value when the PES is scheduled for transmission output */
	time_t created;               /* Object creation time in seconds. Used for purging. */

	enum pid_type_e type;         /* PID_UNDEFINED = 0, PID_AUDIO, PID_VIDEO etc */

	/* Metadata as it pertains to the content of the PES */
	struct {
		int hasSync_MP1L2;
		int hasSync_AC3;
		int hasSync_AAC;
	} audio;

	struct {
		enum SliceType_e sliceType;
		int has_avc_closed_gop;
		int has_avc_filler;
		int has_avc_sps;
		int has_avc_pps;
		int has_avc_aud;
	} video;

	int nalArrayLength;              /* AVC ONLY. Number of items in nals[]. */
	struct ltn_nal_headers_s *nals;  /* AVC ONLY. Array of nal objects. Eg. SEI, AUD, PPS, SPS, IDR, non-IDR slice etc */
};

struct pid_s
{
	struct input_stream_s *stream;   /* parent stream context */
	enum pid_type_e type;            /* Eg. PID_VIDEO, PID_AUDIO */
	enum pid_state_e state;          /* Processing state. Eg. PS_SCHEDULE_NEXT_PACKET */

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

	struct timespec last_pcr_output; /* STC ticks. Last time in ticks we output the STC/PCR  */
	uint8_t pkt_scr[188];            /* A fully formed PCR packet */

	uint64_t count_frames_i;         /* Count of different video slice types: I */
	uint64_t count_frames_b;         /* Count of different video slice types: B */
	uint64_t count_frames_p;         /* Count of different video slice types: P */
	uint64_t count_frames_idr;       /* Number of nal type 5 (AVC) IDR close gop frames */

	/* Video Buffer Verifier (VBV) */
	void *vbv;
	struct vbv_decoder_profile_s dp;

	/* Timing model, where we track all input and output clocks for this pid.
	 * We'll use this history to help us determine new timing for the output
	 * frames when steram switch.
	 */
	pthread_mutex_t  tilistlock;     /* protection for list */
	struct xorg_list tilist;         /* fifo list of (PES) timing objects. */

	int64_t clockAdjustmentPTS;      /* Value we add to each pes inorder to match the alternative input */
	int64_t clockAdjustmentDTS;      /* Value we add to each pes inorder to match the alternative input */

	int64_t lastOutputPTS;           /* Value of last PTS we packetizied*/
	int64_t lastOutputPTSDelta;
	int64_t lastOutputDTS;           /* Value of last DTS we packetizied*/
	int64_t lastOutputDTSDelta;

	int performClockAdjustmentPTS;
	int performClockAdjustmentDTS;
};

struct input_stream_s
{
	struct tool_ctx_s *ctx;  /* parent */
	int nr;                  /* 0..1 */
	char *iname;             /* Eg. udp:/227.1.1.1:4001 */

	void *sm;                       /* StreamModel context */
	int smcomplete;                 /* Is the stream model collected and thus complete? */
	struct ltntstools_pat_s *smpat; /* When smcomplete=1, this model is valid */

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

	struct ltntstools_stream_statistics_s *libstats; /* Transport Stream packet statistics */
};

struct tool_ctx_s
{
	int verbose;                     /* -v option increments this higher and higher */
	int inputNr;                     /* */
	int activeInputNr;               /* 0..inputNr */
	int flushInput;                  /* prepare to switch inputs */

	int output_psip_idx;             /* Index pointer into psip_pkt[n] */
	uint8_t psip_cc[3];              /* Keeping track of the CC for any PSIP packets */
	uint8_t psip_pkt[3][188];        /* Enough space to hold a PAT in psip_pkt[0], and two single stream PMTs in psip_pkt[1] and psip_pkt[2] */

	struct timespec next_time;           /* Current time */
	struct timespec last_psip;           /* Last time a PSIP TS packet were output */
	struct timespec last_q_report;       /* Last time a PES queue report was dumped to console. */
	struct timespec last_codec_report;   /* Last time a PES queue report was dumped to console. */
	struct timespec last_q_purge;        /* Last time the PES queues were purged of old content. */
	struct timespec last_compatability_check; /* Last time we checks that streams 1&2 were compatible. */

	/* Streams. Many input, one output. */
	struct input_stream_s *input_streams[MAX_INPUT_STREAMS];
	struct output_stream_s *outputStream;

	/* Stream scheduling */
	pthread_mutex_t schedule_lock;   /* protection for list */
	uint32_t schedule_idx;           /* Index from 0..schedule_entries, or -1 to indicate inactive. */
	int schedule_entries;            /* Number of pids objects in var schedule[] */
	struct pid_s *schedule[4];       /* Array of pids, we plan to output packets for */
};

void tprintf(const char *fmt, ...);

/* switcher-input.c */
struct input_stream_s *input_stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr);
void                   input_stream_free(struct input_stream_s *stream);
void input_stream_show_codec_stats(struct input_stream_s *is);
void input_stream_prune_history(struct input_stream_s *is);
int  input_stream_model_supported(struct input_stream_s *stream);
int  input_stream_models_compatible(struct input_stream_s *is1, struct input_stream_s *is2);
int  input_stream_flush_to_transition_point(struct input_stream_s *is);

struct pid_s *input_stream_pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_e type);
void          input_stream_pid_free(struct pid_s *pid);
int  input_stream_pid_add(struct input_stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId);
int  input_stream_pid_write(struct pid_s *pid, const uint8_t *pkts, int packetCount);
void input_stream_pid_set_state(struct pid_s *pid, enum pid_state_e state);
enum pid_state_e input_stream_pid_get_state(struct pid_s *pid);

const char *getPidTypeDescription(enum pid_type_e type);
struct pid_s *input_stream_pid_lookup(struct pid_s *pid, struct input_stream_s *is);

/* switcher-output.c */
struct output_stream_s *output_stream_alloc(struct tool_ctx_s *ctx);
void    output_stream_free(struct output_stream_s *os);
int64_t output_get_computed_stc(struct output_stream_s *os);

/* switcher-codecs.h */
struct pes_item_s *pes_item_alloc(struct pid_s *pid, struct ltn_pes_packet_s *pes, struct output_stream_s *os);
void               pes_item_free(struct pes_item_s *item);
void pes_item_nals_dump(struct pes_item_s *item);
void pes_item_nals_free(struct pes_item_s *item);
int  pes_item_nals_alloc(struct pes_item_s *item);
void pes_item_dump(struct pes_item_s *item, int dumpNals);
int  pes_contains_start_of_ac3_sync(const struct ltn_pes_packet_s *pes);
int  pes_contains_start_of_aac_sync(const struct ltn_pes_packet_s *pes);
int  pes_contains_start_of_mp2_sync(const struct ltn_pes_packet_s *pes);
int  ffmpeg_demux_test(const char *filename);

struct timing_item_s *timing_item_alloc(struct pes_item_s *item);
void timing_item_free(struct timing_item_s *ti);
void timing_item_dump(struct timing_item_s *ti);
int timing_item_compute_delta(struct timing_item_s *a, struct timing_item_s *b, int64_t *resultTicks);
