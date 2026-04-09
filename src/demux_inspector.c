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

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"
#include "source-pcap.h"

char *strcasestr(const char *haystack, const char *needle);

enum pidType_e {
	PT_UNDEFINED = 0, PT_AUDIO, PT_VIDEO, PT_OTHER,
};

enum SliceType_e {
	SLICE_UNDEFINED = 0,
	SLICE_I, SLICE_B, SLICE_P
};

struct input_pid_s
{
	struct tool_ctx_s *ctx;
	int enabled;
	uint16_t pidNr;

	enum pidType_e type; /* PT_UNDEFINED = 0, PT_AUDIO, PT_VIDEO, PT_OTHER, etc */

	struct xorg_list pesitemlist; /* list of struct pes_item_s */
};

struct pes_item_s
{
	struct xorg_list list;
	const struct ltn_pes_packet_s *pes;
	enum pidType_e type; /* PT_UNDEFINED = 0, PT_AUDIO, PT_VIDEO, PT_OTHER, etc */

	struct input_pid_s *input;

	struct {
		int hasSync_MP1L2;
		int hasSync_AC3;
		int hasSync_AAC;
	} audio;

	struct {
		enum SliceType_e sliceType;
		int has_avc_sps;
		int has_avc_pps;
		int has_avc_aud;
	} video;

	int nalArrayLength;
	struct ltn_nal_headers_s *nals;
};

struct tool_ctx_s
{
	int   verbose;

	void *src_pcap; /* Source-pcap context */
	char *iname;
	char *pcap_filter;

	void *demux_ctx;

	void *sm; /* StreamModel Context */
	int smcomplete;

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;

	int isRTP;

#define MAX_PIDS 0x2000
	struct input_pid_s pids[MAX_PIDS];

	uint64_t count_frames_i;
	uint64_t count_frames_b;
	uint64_t count_frames_p;
};

//struct input_pid_s;

static int gRunning = 1;
static void signal_handler(int signum)
{
	gRunning = 0;
}

/* For a given pes, look at the vars and stream content.
 * determine of the pes begins with a MP2 sync marker.
 * Returns 1 on success else 0.
 */
static int pes_contains_start_of_mp2_sync(const struct ltn_pes_packet_s *pes)
{
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* MP2 sync word 0xFFF */
	if (pes->data[0] != 0xff)
		return 0;
	/* C = MPEG Version == MP2*/
	if (pes->data[1] != 0xfc)
		return 0;

	return 1; /* MP1/L2 sync found */
}

/* For a given pes, look at the vars and stream content.
 * determine of the pes begins with a MP2 sync marker.
 * Returns 1 on success else 0.
 */
static int pes_contains_start_of_ac3_sync(const struct ltn_pes_packet_s *pes)
{
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* Fixed sync 0x0B77 */
	if (pes->data[0] != 0x0B)
		return 0;
	if (pes->data[1] != 0x77)
		return 0;

	return 1; /* AC3 sync found */
}

static int pes_contains_start_of_aac_sync(const struct ltn_pes_packet_s *pes)
{
	/* FFFn
	adts_fixed_header() {
    syncword                         12 bits  // 0xFFF
    ID                                1 bit   // 0=MPEG-4, 1=MPEG-2
    layer                             2 bits  // always 00
    protection_absent                 1 bit   // 1=no CRC

    profile                           2 bits  // 1 = AAC-LC
    sampling_frequency_index          4 bits
    private_bit                       1 bit
    channel_configuration             3 bits
    original_copy                     1 bit
    home                              1 bit
	}
	*/
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* Fixed sync 0xFFF1 */
	if (pes->data[0] != 0xff)
		return 0;
	if (pes->data[1] != 0xf1)
		return 0;

	return 1; /* AAC ADTS sync found */
}

static void pes_item_nals_dump(struct pes_item_s *item)
{
	for (int i = 0; i < item->nalArrayLength; i++) {
		struct ltn_nal_headers_s *nal = &item->nals[i];
		printf(" nal: %02x [%s]\n", nal->nalType, nal->nalName);
	}
}

static void pes_item_nals_free(struct pes_item_s *item)
{
	if (item->nals) {
		free(item->nals);
		item->nals = NULL;
	}
	item->nalArrayLength = 0;
}

static int pes_item_nals_alloc(struct pes_item_s *item)
{
	struct tool_ctx_s *ctx = item->input->ctx;

//	int reportAll = 0;
//	int result = 0;
	unsigned int sliceType;

	/* Free any existing nals */
	pes_item_nals_free(item);

	/* Turn the PES into a series of NALS */
	if (ltn_nal_h264_find_headers(item->pes->data, item->pes->dataLengthBytes, &item->nals, &item->nalArrayLength) < 0) {
		return -1;
	}

	/* TODO: THIS IS AVC ONLY */
	for (int i = 0; i < item->nalArrayLength; i++) {
		struct ltn_nal_headers_s *nal = &item->nals[i];
		switch (nal->nalType) {
		case 1: /* slice_layer_without_partitioning_rbsp */
		case 2: /* slice_data_partition_a_layer_rbsp */
		case 5: /* slice_layer_without_partitioning_rbsp */
		case 19: /* slice_layer_without_partitioning_rbsp */
			if (h264_nal_get_slice_type_for_nal(nal, &sliceType) == 0) {
				//printf("SLICE TYPE %d, %s\n", sliceType, h264_slice_name_ascii(sliceType));
				if (h264_is_slice_type_iframe(sliceType)) {
					item->video.sliceType = SLICE_I;
					ctx->count_frames_i++;
				} else
				if (h264_is_slice_type_bframe(sliceType)) {
					item->video.sliceType = SLICE_B;
					ctx->count_frames_b++;
				} else
				if (h264_is_slice_type_pframe(sliceType)) {
					item->video.sliceType = SLICE_P;
					ctx->count_frames_p++;
				}
			}
			break;
		case 7:
			item->video.has_avc_sps = 1;
			break;
		case 8:
			item->video.has_avc_pps = 1;
			break;
		case 9:
			item->video.has_avc_aud = 1;
			break;
		}
	}

	return 0; /* Success */
}

static struct pes_item_s * pes_item_alloc(const struct ltn_pes_packet_s *pes, struct input_pid_s *input)
{
	//ltn_pes_packet_dump(pes, "");
	struct pes_item_s *item = calloc(1, sizeof(*item));
	if (item) {
		item->pes = ltn_pes_packet_clone((struct ltn_pes_packet_s *)pes);
		if (!item->pes) {
			free(item);
			return NULL;
		}
		item->type = PT_UNDEFINED;
		item->input = input;

		if (ltn_pes_packet_is_video((struct ltn_pes_packet_s *)item->pes)) {
			//printf("pes contains video\n");
			item->type = PT_VIDEO;

			if (pes_item_nals_alloc(item) < 0) {
				fprintf(stderr, "asked to find nals, no nals found.... unusual, continuiting...\n");
			}
			/* item->video.has_XYZ are now set correctly */

		} else
		if (ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)item->pes)) {
			item->type = PT_AUDIO;
			//printf("pes contains audio\n");
			if (pes_contains_start_of_mp2_sync(pes) == 1) {
				//printf("Contains MP1/L2 sync\n");
				item->audio.hasSync_MP1L2 = 1;
			} else
			if (pes_contains_start_of_ac3_sync(pes) == 1) {
				//printf("Contains AC3 sync\n");
				item->audio.hasSync_AC3 = 1;
			} else
			if (pes_contains_start_of_aac_sync(pes) == 1) {
				//printf("Contains AAC/ADTS sync\n");
				item->audio.hasSync_AAC = 1;
			}
		} else {
			item->type = PT_OTHER;
		}

	}

	return item;
}

static void pes_item_free(struct pes_item_s *item)
{
	pes_item_nals_free(item);

	if (item->pes) {
		ltn_pes_packet_free((struct ltn_pes_packet_s *)item->pes);
		item->pes = NULL;
	}

	free(item);
}

static void pes_item_dump(struct pes_item_s *item)
{
	const struct ltn_pes_packet_s *pes = item->pes;

	char lbl[] = "[?]";

	if (item->type == PT_VIDEO) {
		switch(item->video.sliceType) {
		case SLICE_I: lbl[1] = 'I'; break;
		case SLICE_B: lbl[1] = 'B'; break;
		case SLICE_P: lbl[1] = 'P'; break;
		case SLICE_UNDEFINED: lbl[1] = '?'; break;
		}
	} else {
		/* No slice printing for non video nals */
		lbl[0] = ' ';
		lbl[1] = ' ';
		lbl[2] = ' ';
	}

	printf("%s() pid 0x%04x %s %s pes %p rtt %3dms, pcr %013" PRIi64,
		__func__, item->input->pidNr,
		item->type == PT_VIDEO ? "VIDEO" :
		item->type == PT_AUDIO ? "AUDIO" : "OTHER",
		lbl,
		pes,
		pes->arrivalMs, pes->pcr);
	if (pes->PTS_DTS_flags & 2) {
		printf(", pts %013" PRIi64, pes->PTS);
	}
	if (pes->PTS_DTS_flags & 1) {
		printf(", dts %013" PRIi64, pes->DTS);
	}
	printf("\n");

	//pes_item_nals_dump(item);

}
/* End -- Misc pes function - find a better home for these. */

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount);

#ifdef __APPLE__
#define iphdr ip
#endif

static void *source_pcap_raw_cb(void *userContext, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	if (hdr->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return NULL;

#ifdef __APPLE__
	{
		/* MacOS doesn't give us an etherher, but a loophead 4 byte header instead */
		struct iphdr *iphdr = (struct iphdr *)((u_char *)pkt + 4);
		if (*(pkt + 4) != 0x45) /* Check this is a IP header version 4, 20 bytes long */
			return NULL;
#endif
#ifdef __linux__
	struct ether_header *ethhdr = (struct ether_header *)pkt;
	if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
		struct iphdr *iphdr = (struct iphdr *)((u_char *)ethhdr + sizeof(struct ether_header));
#endif

#ifdef __APPLE__
		if (iphdr->ip_p != IPPROTO_UDP)
			return NULL;
#endif
#ifdef __linux__
		if (iphdr->protocol != IPPROTO_UDP)
			return NULL;
#endif

		struct udphdr *udphdr = (struct udphdr *)((u_char *)iphdr + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udphdr + sizeof(struct udphdr));

		if (ctx->verbose > 2) {
			struct in_addr dstaddr, srcaddr;
#ifdef __APPLE__
			srcaddr.s_addr = iphdr->ip_src.s_addr;
			dstaddr.s_addr = iphdr->ip_dst.s_addr;
#endif
#ifdef __linux__
			srcaddr.s_addr = iphdr->saddr;
			dstaddr.s_addr = iphdr->daddr;
#endif

			char src[24], dst[24];
#ifdef __linux__
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->source));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udphdr->dest));
#endif
#ifdef __APPLE__
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->uh_sport));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udphdr->uh_dport));
#endif

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				
				src, dst,
#ifdef __linux__
				ntohs(udphdr->len),
#endif
#ifdef __APPLE__
				ntohs(udphdr->uh_ulen),
#endif
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

#ifdef __linux__
		int lengthPayloadBytes = ntohs(udphdr->len) - sizeof(struct udphdr);
#endif
#ifdef __APPLE__
		int lengthPayloadBytes = ntohs(udphdr->uh_ulen) - sizeof(struct udphdr);
#endif
		
		if ((lengthPayloadBytes > 12) && ((lengthPayloadBytes - 12) % 188 == 0)) {
			/* It's RTP */
			ptr += 12;
			lengthPayloadBytes -= 12;
		}

		process_transport_buffer(ctx, ptr, lengthPayloadBytes);
	}

	return NULL;
}

void *demux_cb_pes(void *userContext, uint16_t pidNr, struct ltn_pes_packet_s *pes)
{
	struct tool_ctx_s *ctx = userContext; 
	struct input_pid_s *pid = (struct input_pid_s *)&ctx->pids[pidNr & 0x1fff];

	if (pidNr == 0x33) {
		//ltn_pes_packet_dump(pes, "");
	}

	/* Caller DOES NOT OWN the lifespan of the pes object, don't free it. */
	struct pes_item_s *item = pes_item_alloc(pes, pid);

	pes_item_dump(item);

	pes_item_free(item);

	return NULL;
}

static struct ltntstools_demux_callbacks demux_callbacks = 
{
    .cb_pes = (demux_callback_pes)demux_cb_pes,
	.cb_section = NULL,
};

static struct ltntstools_source_pcap_callbacks_s pcap_callbacks = 
{
    .raw = (ltntstools_source_pcap_raw_callback)source_pcap_raw_cb,
};

static void usage(const char *progname)
{
	printf("A tool to demux a stream, this is a test hardness. From a file, live UDP socket stream, or PCAP NIC.\n");
	printf("Usage:\n");
	printf("  -i <url | nicname>   Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n");
    printf("                           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("                       Eg: eno2    (Also see -F)\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -F exact pcap filter. Eg 'host 227.1.20.80 && udp port 4001'\n");
	printf("     DON'T PASS A FILTER WITH MPTS or something with multiple different streams - be very specific, one stream one program\n");
	printf("\nExample:\n");
	printf("  sudo ./tstools_demux_inspector -i eno2 -F 'host 227.1.20.80 && udp port 4001'  -- auto-detect SCTE/video pids from nic\n");
	printf("       ./tstools_demux_inspector -i recording.ts                                 -- auto-detect SCTE/video pids from file\n");
	printf("       ./tstools_demux_inspector -i udp://227.1.20.80:4001                       -- auto-detect SCTE/video pids from socket/stream\n");
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount)
{
	if (ctx->isRTP)
		buf += 12;

	if (ctx->verbose >= 2) {
		for (int j = 0; j < byteCount; j += 188) {
			uint16_t pidnr = ltntstools_pid(buf + j);
			printf("PID %04x : ", pidnr);
			for (int i = 0; i < 8; i++)
				printf("%02x ", buf[j + i]);
			printf("\n");
		}
	}

	/* Allocate a stream model */
	if (ctx->sm == NULL) {
		if (ltntstools_streammodel_alloc(&ctx->sm, NULL) < 0) {
			fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
			exit(1);
		}
	}

	/* Feed a stream model until its complete */
	if (ctx->sm && ctx->smcomplete == 0) {
        struct timeval nowtv;
        gettimeofday(&nowtv, NULL);
		ltntstools_streammodel_write(ctx->sm, &buf[0], byteCount / 188, &ctx->smcomplete, &nowtv);

		/* TODO: Detect model changes dynamically */

		if (ctx->smcomplete) {
			struct ltntstools_pat_s *pat = NULL;
			if (ltntstools_streammodel_query_model(ctx->sm, &pat) == 0) {
				/* Retain the streammodel, we'll release it when we shutdown. */
				ltntstools_pat_dprintf(pat, STDOUT_FILENO);

				if (ltntstools_demux_alloc_from_pat(&ctx->demux_ctx, ctx, &demux_callbacks, pat) < 0) {
					fprintf(stderr, "Unable to allocate demux from pat, hard abort.\n");
					exit(1);
				}
			}
		}
	}
	if (ctx->demux_ctx) {
		ltntstools_demux_write(ctx->demux_ctx, &buf[0], byteCount / 188);
	}
}

static void process_pcap_input(struct tool_ctx_s *ctx)
{
	if (ltntstools_source_pcap_alloc(&ctx->src_pcap, ctx, &pcap_callbacks, ctx->iname, ctx->pcap_filter, (1024 * 1024 * 4)) < 0) {
		fprintf(stderr, "Failed to open source_pcap interface, check permissions (sudo) or syntax.\n");
		return;
	}

	while (gRunning) {
		usleep(50 * 1000);
	}

	ltntstools_source_pcap_free(ctx->src_pcap);
}

static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;
	process_transport_buffer(ctx, pkts, packetCount * 188);

	return NULL;
}

static void *_avio_raw_callback_status(void *userContext, enum source_avio_status_e status)
{
	switch (status) {
	case AVIO_STATUS_MEDIA_START:
		printf("AVIO media starts\n");
		break;
	case AVIO_STATUS_MEDIA_END:
		printf("AVIO media ends\n");
		signal_handler(0);
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}

static void process_avio_input(struct tool_ctx_s *ctx)
{
	if (strcasestr(ctx->iname, "rtp://")) {
		ctx->isRTP = 1;
	}

	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;

	void *srcctx = NULL;
	int ret = ltntstools_source_avio_alloc(&srcctx, ctx, &cbs, ctx->iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return;
	}

	while (gRunning) {
		usleep(50 * 1000);
	}

	ltntstools_source_avio_free(srcctx);
}

int demux_inspector(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Unable to allocate memory for application context, aborting.\n");
		return -1;
	}

	ctx->verbose = 1;
	ctx->mode = MODE_SOURCE_AVIO;

	for (int i = 0; i < MAX_PIDS; i++) {
		xorg_list_init(&ctx->pids[i].pesitemlist);
		ctx->pids[i].pidNr = i;
		ctx->pids[i].ctx = ctx;
	}

	int ch;

	while ((ch = getopt(argc, argv, "?hvi:F:P:V:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->iname = strdup(optarg);
			break;
		case 'F':
			ctx->pcap_filter = strdup(optarg);
			ctx->mode = MODE_SOURCE_PCAP;
			break;
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (getuid() == 0 && getenv("SUDO_UID") && getenv("SUDO_GID") && ctx->mode != MODE_SOURCE_PCAP) {
		usage(argv[0]);
		fprintf(stderr, "\n**** Don't use SUDO against file or udp socket sources, ONLY nic/pcap sources ****.\n\n");
		exit(1);
	}

	if (ctx->iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	signal(SIGINT, signal_handler);

	if (ctx->mode == MODE_SOURCE_AVIO) {
		printf("Mode: AVIO\n");
		process_avio_input(ctx);
	} else
	if (ctx->mode == MODE_SOURCE_PCAP) {
		printf("Mode: PCAP\n");
		process_pcap_input(ctx);
	}

	for (int i = 0; i < MAX_PIDS; i++) {
		if (ctx->pids[i].enabled == 0) {
			continue;
		}
		/* TODO: Free up any list items */
	}
	
	if (ctx->sm) {
		ltntstools_streammodel_free(ctx->sm);
		ctx->sm = NULL;
	}

	if (ctx->iname) {
		free(ctx->iname);
		ctx->iname = NULL;
	}
	
	if (ctx->demux_ctx) {
		ltntstools_demux_free(ctx->demux_ctx);
		ctx->demux_ctx = NULL;
	}

	printf("AVC: I/B/P = %" PRIu64 "/%" PRIu64 "/%" PRIu64 ", %" PRIu64 " slices.\n",
		ctx->count_frames_i, ctx->count_frames_b, ctx->count_frames_p,
		ctx->count_frames_i + ctx->count_frames_b + ctx->count_frames_p);

	free(ctx);

	return 0;
}
