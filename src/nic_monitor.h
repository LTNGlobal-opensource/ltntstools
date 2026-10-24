#ifndef NIC_MONITOR_H
#define NIC_MONITOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <curses.h>
#include <inttypes.h>
#include <pthread.h>
#include <locale.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <libltntstools/ltntstools.h>
#include <libltntstools/histogram.h>
#include <libltntstools/igmp.h>
#include <libltntstools/probes.h>
#include <libklscte35/scte35.h>
#include "source-rcts.h"
#include "xorg-list.h"
#include "parsers.h"
#include "ffmpeg-includes.h"
#include "utils.h"
#include "hash_index.h"
#include "codecs.h"
#include "nic_monitor_ui_buf.h"
#include "nic_monitor_ui_input.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#define MEDIA_MONITOR 0
#if MEDIA_MONITOR
#include "media.h"
#endif

#include <json-c/json.h>

#if KAFKA_REPORTER
#include <librdkafka/rdkafka.h>
#endif

#define FILE_WRITE_INTERVAL 5
#define JSON_WRITE_INTERVAL 1
#define DEFAULT_PCAP_FILTER "udp dst portrange 4000-4999"
#define SCTE35_HISTORY_SECONDS (3 * 60 * 60)

#define DEFAULT_STORAGE_LOCATION "/storage/packet_captures"

#define MEASURE_PCAP_CALLBACK_PERFORMANCE 0

enum payload_type_e {
	PAYLOAD_UNDEFINED = 0,
	PAYLOAD_UDP_TS,
	PAYLOAD_RTP_TS,
	PAYLOAD_A324_CTP,
	PAYLOAD_BYTE_STREAM,
	PAYLOAD_SMPTE2110_20_VIDEO,
	PAYLOAD_SMPTE2110_30_AUDIO,
	PAYLOAD_SMPTE2110_40_ANC,
	PAYLOAD_SRT_TS,
	PAYLOAD_SRT_CTRL,
	PAYLOAD_SRT_ENCRYPTED,
	PAYLOAD_MOO_COWS,
	PAYLOAD_MAX,
};

struct discovered_item_s;

struct tool_context_s
{
	char *ifname;
	enum {
		IF_TYPE_PCAP = 0,
		IF_TYPE_MPEGTS_FILE,
		IF_TYPE_MPEGTS_AVDEVICE,
	} iftype;
	int fileLoops; /* Boolean. A file input, should it loop and repeat at end of file? */
	double fileLoopPct; /* How much (pct) has the file loop played out? */
	char *recordingDir;
	int verbose;
	int monitor;
	time_t startTime, endTime;
	int iatMax;
	int automaticallyRecordStreams;
	int automaticallyJSONProbeStreams;
	int recordWithSegments;
	int recordAsTS;
	int showUIOptions;
	int skipFreeSpaceCheck;
	int gatherH264Metadata;
	int gatherH264MetadataPID;
	int reportRTPHeaders;
	int measureSEILatencyAlways;
	int reportProcessMemoryUsage;
	int reportMicrobursts;

	pthread_t pcap_threadId;
	int pcap_threadTerminate, pcap_threadRunning, pcap_threadTerminated;

	pthread_t stats_threadId;
	int stats_threadTerminate, stats_threadRunning, stats_threadTerminated;

	pthread_t ui_threadId;
	int ui_threadTerminate, ui_threadRunning, ui_threadTerminated;
	/* Every ncurses call is made with this lock held (ncurses is not thread safe). */
	pthread_mutex_t ui_threadLock;

	/* UI state shared with other threads. Everything else the UI uses is
	 * owned by the UI thread (nic_monitor_ui.c).
	 */
	uint32_t uiCursorId;          /* Stream id under the cursor, 0 = none. Written by the UI
	                               * thread only; read with __atomic_load_n. */
	int uiMouseEnabled;           /* Atomic. Written by the main thread. */
	int uiDisableMouse;           /* --no-mouse */
	struct ui_event_queue_s uiEvents;   /* Main thread -> UI thread: navigation keys, mouse */
	struct ui_message_s uiMessage;      /* Any thread -> MESSAGE line */

	char json_http_url[256];
	pthread_t json_threadId;
	int json_threadTerminate, json_threadRunning, json_threadTerminated;
	pthread_mutex_t lockJSONPost;
	struct xorg_list listJSONPost;
	int jsonSocket;
	struct sockaddr_in jsonSin;

	int rest_api_port;
	int rest_api_socket;
	pthread_t rest_api_threadId;
	int rest_api_threadTerminate, rest_api_threadRunning, rest_api_threadTerminated;

#if KAFKA_REPORTER
	pthread_t kafka_threadId;
	int kafka_threadTerminate, kafka_threadRunning, kafka_threadTerminated;
#endif

	/* PCAP */
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char *pcap_filter;
	int snaplen;
	int bufferSize;
	struct pcap_stat pcap_stats; /* network loss and drop statistics */
	struct pcap_stat pcap_stats_startup; /* network loss and drop statistics */
	int64_t pcap_free_miss;
	int64_t pcap_dispatch_miss;
	int64_t pcap_malloc_miss;
	int64_t pcap_mangled_list_items;

	/* queue rebalancing */
	int rebalance_last_buffers_used;
	time_t rebalance_last_buffer_time;
	int rebalance_buffers_used;
	time_t rebalance_queue_time_last;

	/* list of discovered addresses and related statistics. */
	pthread_mutex_t lock;
	struct xorg_list list;
	time_t lastListHousekeeping;
	struct hash_index_s *hashIndex;
	uint64_t cacheHit, cacheMiss;
	double cacheHitRatio;

	/* All pcap buffers go into a thread and are handled in a non-realtime thread. */
	pthread_mutex_t lockpcap;
	struct xorg_list listpcapFree;
	int listpcapFreeDepth;
	struct xorg_list listpcapUsed;
	int listpcapUsedDepth;

	/* File based statistics */
	char *file_prefix;
	int file_write_interval;
	time_t file_prefix_next_write_time;

	/* Json probe writes */
	int json_write_interval;
	time_t json_next_write_time;

	/* Detailed file based statistics */
	char *detailed_file_prefix;
	time_t detailed_file_prefix_next_write_time;

	/* Stats reset time */
	time_t lastResetTime;
	int freezeDisplay;

	/* UDP Socket stats */
	void *procNetUDPContext;
	int showForwardOptions;       /* Atomic. 'F' pressed, waiting for 7/8/9 or q. */
	time_t lastSocketReport;

	/* URL Forwarding options */
#define MAX_URL_FORWARDERS 3
	struct {
		char addr[64];
		int port;
		char uilabel[80];
	} url_forwards[MAX_URL_FORWARDERS];

	/* IGMP joins held open while monitoring a pcap interface. */
#define MAX_IGMP_JOIN_ADDRESSES 64
	int igmpJoinCount;
	struct parser_ippid_s igmpJoinAddress[MAX_IGMP_JOIN_ADDRESSES];
	void *igmpJoinHandle[MAX_IGMP_JOIN_ADDRESSES];

	/* SRT Ingest, and packet reframing */
	struct ltntstools_reframer_ctx_s *reframer;

	/* Track tool memory usage */
	struct statm_context_s memUsage;
	char memUsageStatus[80];

};

struct json_item_s
{
	struct xorg_list list;
	unsigned char *buf;
	int lengthBytes;
	int lengthBytesMax;
};

int json_initialize(struct tool_context_s *ctx);
void json_free(struct tool_context_s *ctx);

struct json_item_s *json_item_alloc(struct tool_context_s *ctx, int lengthBytesMax);
int json_item_post_http(struct tool_context_s *ctx, struct json_item_s *item);
int json_item_post_socket(struct tool_context_s *ctx, struct json_item_s *item);
void json_item_free(struct tool_context_s *ctx, struct json_item_s *item);
int json_queue_push(struct tool_context_s *ctx, struct json_item_s *item);
struct json_item_s *json_queue_pop(struct tool_context_s *ctx);
struct json_item_s *json_queue_peek(struct tool_context_s *ctx);

int  rest_api_initialize(struct tool_context_s *ctx);
void rest_api_free(struct tool_context_s *ctx);
void *rest_api_thread_func(void *p);
json_object *rest_api_transport_streams_json(struct tool_context_s *ctx);
json_object *rest_api_transport_pids_json(struct tool_context_s *ctx);
json_object *rest_api_stream_models_json(struct tool_context_s *ctx);
json_object *rest_api_stream_logs_json(struct tool_context_s *ctx);
json_object *rest_api_iat_histograms_json(struct tool_context_s *ctx);
json_object *rest_api_clock_reports_json(struct tool_context_s *ctx);
json_object *rest_api_scte35_json(struct tool_context_s *ctx);
const char *rest_api_openapi_json(void);

#if KAFKA_REPORTER
struct kafka_item_s
{
	struct xorg_list list;
	unsigned char *buf;
	int lengthBytes;
	int lengthBytesMax;
	struct discovered_item_s *di;
};

#endif

struct pcap_item_s
{
	struct xorg_list list;
	struct pcap_pkthdr *h;
	u_char *pkt;
};

void pcap_update_statistics(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt);
int pcap_queue_initialize(struct tool_context_s *ctx);
int pcap_queue_push(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt);
int pcap_queue_service(struct tool_context_s *ctx);
int pcap_queue_rebalance(struct tool_context_s *ctx);
void pcap_queue_free(struct tool_context_s *ctx);

struct display_doc_s
{
	pthread_mutex_t lock;
	int lineCount;
	uint8_t **lines;

	int displayLineFrom;
	int pageSize;
	int maxPageSize;
};
void display_doc_initialize(struct display_doc_s *doc);
void display_doc_free(struct display_doc_s *doc);
int  display_doc_append(struct display_doc_s *doc, const char *line);
int  display_doc_append_cc_error(struct display_doc_s *doc, uint16_t pid, time_t *when);
int  display_doc_append_with_time(struct display_doc_s *doc, const char *msg, time_t *when);

struct scte35_pid_item_s
{
	struct xorg_list list;
	uint16_t pid;
	uint16_t videoPid;
	void *sectionExtractor;
	int64_t lastVideoPTS;
	uint64_t messageCount;
};

struct scte35_message_item_s
{
	struct xorg_list list;
	time_t receivedAt;
	uint16_t pid;
	uint16_t videoPid;
	int64_t videoPTS;
	int crcValid;
	int parseOk;
	uint64_t sequenceNumber;
	size_t sectionLengthBytes;
	uint8_t *section;
	char *json;
};

void scte35_monitor_free(struct discovered_item_s *di);
void scte35_monitor_write(struct discovered_item_s *di, const uint8_t *pkts, uint32_t pktCount);
void scte35_monitor_prune(struct discovered_item_s *di, time_t now);

struct srt_control_pkt_hdr_s
{
	uint32_t seq_nr; // [15] = 1 (control), [14:0] = control type
	uint32_t msg_nr; // ACK=0x0002, NAK=0x0003, HANDSHAKE=0x0000, etc.
	uint32_t timestamp; // Timestamp in microseconds
	uint32_t dst_socket_id; // SRT connection ID
} __attribute__((packed));
#define SRT__IS_DATA_PACKET(p)       ((ntohl(p->seq_nr) & 0x80000000) == 0)
#define SRT__IS_DATA_ENCRYPTED(p)    ((ntohl(p->msg_nr) & 0x18000000) == 0)
#define SRT__IS_DATA_RETRANMITTED(p) ((ntohl(p->seq_nr) & 0x04000000) == 0)

struct discovered_item_s
{
	struct xorg_list list;

	struct tool_context_s *ctx;

	/* Unique for the life of the process, never reused. 0 is never a valid id. */
	uint32_t id;

	enum payload_type_e payloadType;
	int recordAsTS;

/* Tagged by the operator for a batch command (Space / S). Commands act on the
 * tagged streams, or on the cursor stream when nothing is tagged.
 */
#define DI_STATE_TAGGED					(1 << 0)
#define DI_STATE_CC_ERROR				(1 << 1)
#define DI_STATE_PCAP_RECORD_START		(1 << 2)
#define DI_STATE_PCAP_RECORDING			(1 << 3)
#define DI_STATE_PCAP_RECORD_STOP		(1 << 4)
#define DI_STATE_SHOW_PIDS				(1 << 5)
#define DI_STATE_SHOW_TR101290			(1 << 6)
#define DI_STATE_DST_DUPLICATE			(1 << 7)
#define DI_STATE_SHOW_IAT_HISTOGRAM		(1 << 8)
#define DI_STATE_HIDDEN					(1 << 9)
#define DI_STATE_SHOW_STREAMMODEL		(1 << 10)
#define DI_STATE_SHOW_PROCESSES			(1 << 11)
#define DI_STATE_STREAM_FORWARD_START	(1 << 12)
#define DI_STATE_STREAM_FORWARDING		(1 << 13)
#define DI_STATE_STREAM_FORWARD_STOP	(1 << 14)
#define DI_STATE_JSON_PROBE_ACTIVE		(1 << 15)
#define DI_STATE_SHOW_SCTE35			(1 << 16)
#define DI_STATE_SHOW_STREAM_LOG		(1 << 17)
#define DI_STATE_SHOW_CLOCKS			(1 << 18)
	unsigned int state;

	time_t firstSeen;
	time_t lastUpdated;
	time_t lastStreamCCError;
	struct ether_header ethhdr;
#ifdef __APPLE__
#define iphdr ip
	struct ip iphdr;
#endif
#ifdef __linux__
	struct iphdr iphdr;
#endif
	struct udphdr udphdr;

	/* This object gets put into a quick lookup cache, using a hash
	 * calculated form the ipadress and other things.
	 * We need to store this in the object so we know how to remove
	 * it form the cache when we're destroyed.
	 */
	uint16_t cacheHashKey;

	/* PID Statistics */
	struct ltntstools_stream_statistics_s *stats;

	/* Each time we write stats to a file, we cache the last write
	 * here. When we write the files, if the CC has changed
	 * between the current stats and the statsToFIle count,
	 * we make that obvious in the files, for easier operator
	 * parsing.
	 */
	struct ltntstools_stream_statistics_s *statsToFileSummary;
	uint64_t statsToFileDetailed_ccErrors;
	uint64_t statsToUI_ccErrors;

	/* File output */
	char filename[128];
	char detailed_filename[128];

	/* UI ASCII labels */
	char srcaddr[24];
	char dstaddr[24];
	uint32_t dstport;
	uint32_t srcOriginRemoteHost; /* Is the stream transmitted from a remote or local server? */

	/* IAT */
	int iat_lwm_us; /* IAT low watermark (us), measurement of UDP receive interval */
	int iat_hwm_us; /* IAT high watermark (us), measurement of UDP receive interval */
	int iat_cur_us; /* IAT current measurement (us) */
	int iat_hwm_us_last_nsecond; /* IAT high watermark (us), for the last Nsecond, measurement of UDP receive interval */
	int iat_hwm_us_last_nsecond_accumulator; /* IAT high watermark (us), for the last Nsecond, measurement of UDP receive interval */
	time_t iat_hwm_us_last_nsecond_time; /* time the per-second IAT measurement reports to. */
	struct timeval iat_last_frame; /* Timestamp of last UDP frame for this entity. */

	pthread_mutex_t bitrateBucketLock;
	int bitrate_hwm_us_10ms; /* bitrate high watermark (us), measurement for a 10ms interval */
	int bitrate_hwm_us_10ms_last_nsecond; /* IAT high watermark (us), for the last Nsecond, measurement of UDP receive interval */
	int bitrate_hwm_us_10ms_last_nsecond_accumulator; /* IAT high watermark (us), for the last Nsecond, measurement of UDP receive interval */
	time_t bitrate_hwm_us_10ms_last_nsecond_time; /* time the per-second IAT measurement reports to. */
	int bitrate_hwm_us_100ms; /* bitrate high watermark (us), measurement for a 10ms interval */
	int bitrate_hwm_us_100ms_last_nsecond; /* IAT high watermark (us), for the last Nsecond, measurement of UDP receive interval */
	int bitrate_hwm_us_100ms_last_nsecond_accumulator; /* IAT high watermark (us), for the last Nsecond, measurement of UDP receive interval */
	time_t bitrate_hwm_us_100ms_last_nsecond_time; /* time the per-second IAT measurement reports to. */

	/* PCAP recording */
	void *pcapRecorder;
	time_t lastTimeFSFreeSpaceCheck;

	/* IAT Histogram */
	struct ltn_histogram_s *packetIntervals;
	void *packetIntervalAverages;
	time_t packetIntervalAveragesLastExpire;
	void *packetPayloadSizeBits;

	/* PSIP Tree / Stream Model */
	void *streamModel;

	/* Encoder Specifics */
	int isLTNEncoder;
	void *LTNLatencyProbe;

	/* Payload discovery */
	int discovery_unidentified;
	int a324_found;
	int smpte2110_video_found;
	int smpte2110_audio_found;
	int smpte2110_anc_found;

	/* Stream Forwarding */
	int forwardSlotNr; /* 7/8/9 else stream is not forwarding. */
	AVIOContext *forwardAVIO;
	char forwardURL[64];

	/* H264 specific statistics */
	pthread_mutex_t h264_sliceLock;
	void *h264_slices; /* We count each different kind of slice that we see */

	pthread_mutex_t h264_metadataLock;
	void *h264_metadata_parser;
	char h264_video_colorspace[64];
	char h264_video_format[64];

	/* H265/HEVC specific statistics */
	pthread_mutex_t h265_metadataLock;
	void *h265_metadata_parser;
	char h265_video_colorspace[64];
	char h265_video_format[64];

	/* TR101290 */
	void *trHandle;
	pthread_mutex_t trLock;
	int trCount;
	struct ltntstools_tr101290_alarm_s *trArray;

	/* SCTE-35 */
	pthread_mutex_t scte35Lock;
	struct xorg_list listSCTE35Pids;
	struct xorg_list listSCTE35Messages;
	uint64_t scte35MessageCount;
	time_t lastSCTE35Discover;

	/* RTP Analaysis - Only used when payloadType == PAYLOAD_RTP_TS. */
	struct rtp_hdr_analyzer_s rtpAnalyzerCtx;

#if KAFKA_REPORTER
	struct kafka_ctx_s {
		rd_kafka_conf_t       *conf;
		rd_kafka_topic_conf_t *topic_conf;
		rd_kafka_t            *rk;
		rd_kafka_topic_t      *rkt;
		char                   hostname[128];
		char                   errstr[512];
		char                   topicName[64];

		pthread_mutex_t        listLock;
		struct xorg_list       list;
	} kafka;
#endif

	struct display_doc_s doc_stream_log;
	struct display_doc_s doc_scte35;
	int hasHiddenDuplicates;
	char warningIndicatorLabel[8]; /* ARray of single characters, shows warning flags to operator. */

	/* SRT Protocol */
	struct srt_control_pkt_hdr_s srt_header_last;
	uint64_t srt_retransmittion_count;

	/* PCR pids found in the stream model by the stats thread
	 * (discovered_items_periodic), applied to di->stats by the pcap thread,
	 * which owns di->stats (discovered_item_apply_pending_pcr).
	 */
#define DI_PCR_PIDS_MAX 16
	pthread_mutex_t pcrPidLock;
	uint16_t pcrPidPending[DI_PCR_PIDS_MAX];
	int pcrPidPendingCount;
	int pcrPidPendingReady;   /* Atomic */
};

const char *payloadTypeDesc(enum payload_type_e pt);

void discovered_item_free(struct discovered_item_s *di);
void discovered_items_free(struct tool_context_s *ctx);
struct discovered_item_s *discovered_item_alloc(struct tool_context_s *ctx, struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr, uint16_t hashKey);

struct discovered_item_s *discovered_item_findcreate(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr);

void discovered_item_json_summary(struct tool_context_s *ctx, struct discovered_item_s *di);
void discovered_item_fd_summary(struct tool_context_s *ctx, struct discovered_item_s *di, int fd);

void discovered_items_console_summary(struct tool_context_s *ctx);
void discovered_items_housekeeping(struct tool_context_s *ctx);

/* For a given item, open a detailed stats file on disk, append the current stats, close it. */
void discovered_item_detailed_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di, int write_banner);

/* For a given item, open a stats file on disk, append the current stats, close it. */
void discovered_item_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di, int write_banner);

void discovered_item_warningindicators_update(struct tool_context_s *ctx, struct discovered_item_s *di);

/* Set or clear the state field bitmask. Atomic: safe from any thread. */
void discovered_item_state_set(struct discovered_item_s *di, unsigned int state);
void discovered_item_state_clr(struct discovered_item_s *di, unsigned int state);
unsigned int discovered_item_state_get(struct discovered_item_s *di, unsigned int state);

void discovered_items_file_summary(struct tool_context_s *ctx, int write_banner);
void discovered_items_file_detailed(struct tool_context_s *ctx, int write_banner);
void discovered_items_json_summary(struct tool_context_s *ctx);
#if KAFKA_REPORTER
void discovered_items_kafka_summary(struct tool_context_s *ctx);
#endif
void discovered_items_stats_reset(struct tool_context_s *ctx);

void discovered_items_abort(struct tool_context_s *ctx);

/* Tags, and the command target: the tagged streams, or the cursor stream
 * (ctx->uiCursorId) when nothing is tagged. All take ctx->lock.
 */
void discovered_items_tag_all(struct tool_context_s *ctx);
void discovered_items_tag_none(struct tool_context_s *ctx);
int  discovered_items_tag_toggle_id(struct tool_context_s *ctx, uint32_t id);
/* Switch the PSIP model report on for one stream (double-click). Returns 1
 * if it was switched on, 0 if it was already on, -1 if there is no such stream.
 */
int  discovered_items_show_streammodel_id(struct tool_context_s *ctx, uint32_t id);
/* Caller holds ctx->lock. */
int  discovered_items_any_tagged_locked(struct tool_context_s *ctx);
int  discovered_item_is_target_locked(struct tool_context_s *ctx, struct discovered_item_s *di, int anyTagged);
/* Number of streams the next command would act on. */
int  discovered_items_target_count(struct tool_context_s *ctx);

/* Periodic stream maintenance that used to happen as a side effect of
 * drawing the UI (payload type fallback, PCR pid registration, H.264 slice
 * pid, SCTE-35 history pruning). Called from the stats thread, with or
 * without -M. Takes ctx->lock.
 */
void discovered_items_periodic(struct tool_context_s *ctx, time_t now);

/* Called by the pcap thread for each packet; cheap unless PCR pids are pending. */
void discovered_item_apply_pending_pcr(struct discovered_item_s *di);

void discovered_items_select_record_toggle(struct tool_context_s *ctx);
void discovered_items_select_show_pids_toggle(struct tool_context_s *ctx);
void discovered_items_select_show_tr101290_toggle(struct tool_context_s *ctx);
void discovered_items_select_show_processes_toggle(struct tool_context_s *ctx);
void discovered_items_select_show_iats_toggle(struct tool_context_s *ctx);
void discovered_items_select_show_clocks_toggle(struct tool_context_s *ctx);
void discovered_items_select_hide(struct tool_context_s *ctx);
void discovered_items_unhide_all(struct tool_context_s *ctx);
void discovered_items_select_show_streammodel_toggle(struct tool_context_s *ctx);
void discovered_items_select_forward_toggle(struct tool_context_s *ctx, int slotNr);
void discovered_items_select_json_probe_toggle(struct tool_context_s *ctx);
void discovered_items_select_scte35_toggle(struct tool_context_s *ctx);
void discovered_items_select_show_stream_log_toggle(struct tool_context_s *ctx);


/* TR101290 */
int     nic_monitor_tr101290_alloc(struct discovered_item_s *di);
ssize_t nic_monitor_tr101290_write(struct discovered_item_s *di, const uint8_t *pkts, size_t packetCount);
void    nic_monitor_tr101290_free(struct discovered_item_s *di);
void    nic_monitor_tr101290_reset(struct discovered_item_s *di);

/* Called from the UI thread while building a frame; writes into buf. */
void    nic_monitor_tr101290_draw_ui(struct discovered_item_s *di, struct ui_buf_s *buf, int *row, int p1col, int p2col);

/* UI (nic_monitor_ui.c) */
void   *nic_monitor_ui_thread_func(void *p);
/* 1 for keys the UI thread handles itself (navigation, focus, help). */
int     nic_monitor_ui_is_ui_key(int key);
/* Execute an operator command key (P, C, R, F, q, ...). Safe from the main
 * thread and the UI thread (mouse clicks on HINTS). Returns 1 if the key was
 * a command, else 0. Implemented in nic_monitor.c.
 */
int     nic_monitor_ui_command(struct tool_context_s *ctx, int key);

#if KAFKA_REPORTER
/* Kafka */
int  kafka_initialize(struct discovered_item_s *di);
void kafka_free(struct discovered_item_s *di);
struct kafka_item_s *kafka_item_alloc(struct discovered_item_s *di, int lengthBytesMax);
int  kafka_queue_push(struct discovered_item_s *di, struct kafka_item_s *item);
int  kafka_queue_process(struct discovered_item_s *di);
#endif

#endif /* NIC_MONITOR_H */
