/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

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

char *strcasestr(const char *haystack, const char *needle);

struct tool_ctx_s
{
	int   verbose;
	int   scte35PID;
	void *se; /* SectionExtractor Context */

	int   videoPID;
	int   streamId;
	void *pe; /* PesExtractor Context */

	int64_t lastVideoPTS;

	void *src_pcap; /* Source-pcap context */
	char *iname;
	char *pcap_filter;

	int msgs;

	void *sm; /* StreamModel Context */
	int smcomplete;

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;

	int isRTP;

};

static int gRunning = 1;
static void signal_handler(int signum)
{
	gRunning = 0;
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount);

#ifdef __APPLE__
#define iphdr ip
#endif

void *source_pcap_raw_cb(void *userContext, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	if (hdr->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return NULL;

	struct ether_header *ethhdr = (struct ether_header *)pkt;
	if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
		struct iphdr *iphdr = (struct iphdr *)((u_char *)ethhdr + sizeof(struct ether_header));

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
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->source));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udphdr->dest));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				
				src, dst,
				ntohs(udphdr->len),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		int lengthPayloadBytes = ntohs(udphdr->len) - sizeof(struct udphdr);
		
		if ((lengthPayloadBytes > 12) && ((lengthPayloadBytes - 12) % 188 == 0)) {
			/* It's RTP */
			ptr += 12;
			lengthPayloadBytes -= 12;
		}

		process_transport_buffer(ctx, ptr, lengthPayloadBytes);
	}

	return NULL;
}

struct ltntstools_source_pcap_callbacks_s pcap_callbacks = 
{
    .raw = (ltntstools_source_pcap_raw_callback)source_pcap_raw_cb,
};

void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	ctx->lastVideoPTS = pes->PTS;

	if (ctx->verbose >= 2) {
		ltn_pes_packet_dump(pes, "");
	}

	ltn_pes_packet_free(pes);

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to display the SCTE35 packets from a file, live UDP socket stream, or PCAP NIC.\n");
	printf("Optionally, follow the video pid and report PTS values during each trigger.\n");
	printf("Usage:\n");
	printf("  -i <url | nicname>   Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n");
    printf("                           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("                       Eg: eno2    (Also see -F)\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -P 0xnnnn PID containing the SCTE35 messages (Optional)\n");
	printf("  -V 0xnnnn PID containing the video stream (Optional)\n");
	printf("  -F exact pcap filter. Eg 'host 227.1.20.80 && udp port 4001'\n");
	printf("     DON'T PASS A FILTER WITH MPTS or something with multiple different streams - be very specific, one stream one program\n");
	printf("\nExample:\n");
	printf("  sudo ./tstools_scte35_inspector -i eno2 -F 'host 227.1.20.80 && udp port 4001'  -- auto-detect SCTE/video pids from nic\n");
	printf("       ./tstools_scte35_inspector -i recording.ts                                 -- auto-detect SCTE/video pids from file\n");
	printf("       ./tstools_scte35_inspector -i recording.ts -V 0x1e1 -P 0x67                -- Disable auto-detect force decode of pid 0x67\n");
	printf("       ./tstools_scte35_inspector -i udp://227.1.20.80:4001                       -- auto-detect SCTE/video pids from socket/stream\n");
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount)
{
	if (ctx->isRTP)
		buf += 12;

	if (ctx->verbose >= 2) {
		for (int j = 0; j < byteCount; j += 188) {
			uint16_t pidnr = ltntstools_pid(buf + j);
			if (pidnr == ctx->scte35PID) {
				printf("PID %04x : ", ctx->scte35PID);
				for (int i = 0; i < 188; i++)
					printf("%02x ", buf[j + i]);
				printf("\n");
			}
		}
	}

	if (ctx->sm == NULL && ctx->scte35PID == 0) {
		if (ltntstools_streammodel_alloc(&ctx->sm, NULL) < 0) {
			fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
			exit(1);
		}
	}

	if (ctx->sm && ctx->smcomplete == 0 && ctx->scte35PID == 0) {
		ltntstools_streammodel_write(ctx->sm, &buf[0], byteCount / 188, &ctx->smcomplete);

		if (ctx->smcomplete) {
			struct ltntstools_pat_s *pat = NULL;
			if (ltntstools_streammodel_query_model(ctx->sm, &pat) == 0) {

				/* Walk all the services, find the first service with a SCTE35 service.
				 * Query video and SCTE pid.
				 */
				int e = 0;
				struct ltntstools_pmt_s *pmt;
				uint16_t scte35pid;
				while (ltntstools_pat_enum_services_scte35(pat, &e, &pmt, &scte35pid) == 0) {

					uint8_t estype;
					uint16_t videopid;
					if (ltntstools_pmt_query_video_pid(pmt, &videopid, &estype) < 0)
						continue;

					printf("DEBUG: Found program %5d, scte35 pid 0x%04x, video pid 0x%04x\n",
						pmt->program_number,
						scte35pid,
						videopid);

					ctx->scte35PID = scte35pid;
					ctx->videoPID = videopid;
					break; /* TODO: We only support ehf first SCTE35 pid (SPTS) */
				}

				//ltntstools_pat_dprintf(pat, 0);
				ltntstools_pat_free(pat);
			}
		}
	}

	if (ctx->videoPID && ctx->pe == NULL) {
		if (ltntstools_pes_extractor_alloc(&ctx->pe, ctx->videoPID, ctx->streamId,
				(pes_extractor_callback)pe_callback, ctx) < 0) {
			fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
			exit(1);
		}
		ltntstools_pes_extractor_set_skip_data(ctx->pe, 1);
	}

	if (ctx->scte35PID && ctx->se == NULL) {
		if (ltntstools_sectionextractor_alloc(&ctx->se, ctx->scte35PID, 0xFC /* SCTE35 Table ID */) < 0) {
			fprintf(stderr, "\nUnable to allocate sectionextractor object.\n\n");
			exit(1);
		}
	}

	if (ctx->pe) {
		ltntstools_pes_extractor_write(ctx->pe, &buf[0], byteCount / 188);
	}

	int secomplete = 0;
	int crcValid = 0;
	if (ctx->se) {
		ltntstools_sectionextractor_write(ctx->se, &buf[0], byteCount / 188, &secomplete, &crcValid);
	}

	if (secomplete && crcValid == 0) { 
			printf("<-- Trigger %d --------------------------------------------------->\n", ++ctx->msgs);
			time_t now = time(0);
			printf("SCTE35 message with invalid CRC (skipped), on pid 0x%04x @ %s", ctx->scte35PID, ctime(&now));
	} else
	if (secomplete && crcValid) {
		unsigned char dst[1024];
		memset(dst, 0, sizeof(dst));
		int len = ltntstools_sectionextractor_query(ctx->se, &dst[0], sizeof(dst));
		if (len > 0) {

			printf("<-- Trigger %d --------------------------------------------------->\n", ++ctx->msgs);

			time_t now = time(0);
			printf("SCTE35 message on pid 0x%04x @ %s", ctx->scte35PID, ctime(&now));
			if (ctx->verbose > 0) {
				for (int i = 1; i <= len; i++) {
					if (i == 1 || i % 16 == 1)
						printf("\n  -> ");
					printf("%02x ", dst[i - 1]);
				}
				printf("\n");
				if (len % 16)
					printf("\n");
			}

			if (ctx->pe && ctx->lastVideoPTS) {

				char *t = NULL;
				ltntstools_pts_to_ascii(&t, ctx->lastVideoPTS);

				printf("Video pid 0x%04x last pts %" PRIi64 " [ %s ]\n\n",
					ctx->videoPID,
					ctx->lastVideoPTS,
					t);

				if (t)
					free(t);
			}

			struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(dst, len);
			if (s) {
				/* Dump struct to console */
				if (ctx->videoPID && ctx->lastVideoPTS)
					s->user_current_video_pts = ctx->lastVideoPTS;
				scte35_splice_info_section_print(s);
				scte35_splice_info_section_free(s);
				printf("\n");
				fflush(0);
			} else {
				printf("SCTE35 trigger %d did not parse reliably, skipping.\n\n", ctx->msgs);
				fflush(0);
			}
		}
	}
}

static void process_pcap_input(struct tool_ctx_s *ctx)
{
	if (ltntstools_source_pcap_alloc(&ctx->src_pcap, ctx, &pcap_callbacks, ctx->iname, ctx->pcap_filter) < 0) {
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

int scte35_inspector(int argc, char *argv[])
{
	struct tool_ctx_s s_ctx = { 0 };
	struct tool_ctx_s *ctx = &s_ctx;
	ctx->verbose = 1;
	ctx->streamId = 0xe0; /* Default PES video stream ID */
	ctx->mode = MODE_SOURCE_AVIO;

	int ch;

	while ((ch = getopt(argc, argv, "?hvi:F:P:V:S:")) != -1) {
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
		case 'P':
			if ((sscanf(optarg, "0x%x", &ctx->scte35PID) != 1) || (ctx->scte35PID > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'V':
			if ((sscanf(optarg, "0x%x", &ctx->videoPID) != 1) || (ctx->videoPID > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'S':
			if ((sscanf(optarg, "0x%x", &ctx->streamId) != 1) || (ctx->streamId > 0xff)) {
				usage(argv[0]);
				exit(1);
			}
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

	if (ctx->mode == MODE_SOURCE_AVIO && ctx->videoPID && ctx->streamId == 0) {
		usage(argv[0]);
		fprintf(stderr, "\n-V mean that -S becomes mandatory.\n\n");
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

	if (ctx->pe) {
		ltntstools_pes_extractor_free(ctx->pe);
	}

	if (ctx->se) {
		ltntstools_sectionextractor_free(ctx->se);
	}
	
	if (ctx->sm) {
		ltntstools_streammodel_free(ctx->sm);
	}

	if (ctx->iname) {
		free(ctx->iname);
	}
	
	return 0;
}


