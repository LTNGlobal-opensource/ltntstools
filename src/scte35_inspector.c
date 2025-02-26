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

enum pid_type_e {
	PT_UNKNOWN = 0,
	PT_SCTE35,
	PT_OP47,
	PT_VIDEO,
};

struct input_pid_s
{
	struct tool_ctx_s *ctx;
	int enabled;
	enum pid_type_e payloadType;
	uint16_t pid;

	void *se; /* SectionExtractor Context */
	void *pe; /* PesExtractor Context */

	int SCTEMessageCount;

	uint16_t videoPid;
	int64_t lastVideoPTS;
};

struct tool_ctx_s
{
	int   verbose;
	int   outputJSON;

	void *src_pcap; /* Source-pcap context */
	char *iname;
	char *pcap_filter;

	//int msgs;

	void *sm; /* StreamModel Context */
	int smcomplete;

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;

	int isRTP;

#define MAX_PIDS 0x2000
	struct input_pid_s pids[MAX_PIDS];

	int totalOrderedPids;
	struct input_pid_s *pidsOrdered[MAX_PIDS];
};

static void dumpPid(struct tool_ctx_s *ctx, struct input_pid_s *p)
{
	printf("pid[0x%04x].pid = 0x%04x, pt = %d, videoPid = 0x%04x, pe = %p, se = %p\n",
		p->pid, p->pid, p->payloadType, p->videoPid, p->pe, p->se);
}

static void dumpPids(struct tool_ctx_s *ctx)
{
	for (int i = 0; i < MAX_PIDS; i++) {
		if (ctx->pids[i].enabled) {
			dumpPid(ctx, &ctx->pids[i]);
		}
	}
}

static void setPidType(struct tool_ctx_s *ctx, uint16_t pid, enum pid_type_e pt)
{
	ctx->pids[pid].enabled = 1;
	ctx->pids[pid].payloadType = pt;
	ctx->pids[pid].pid = pid;
	ctx->pids[pid].ctx = ctx;

	/* Put this into a sorted array for optimized lookup */
	for (int i = 0; i < MAX_PIDS; i++) {
		if (ctx->pidsOrdered[i] == 0) {
			ctx->pidsOrdered[i] = &ctx->pids[pid];
			ctx->totalOrderedPids++;
			break;
		}
	}
}

static int countPidsByPayloadType(struct tool_ctx_s *ctx, enum pid_type_e pt)
{
	int cnt = 0;
	for (int i = 0; i < MAX_PIDS; i++) {
		if (ctx->pids[i].enabled == 0) {
			continue;
		}
		if (ctx->pids[i].payloadType == pt) {
			cnt++;
		}
	}

	return cnt;
}

struct input_pid_s;

static int gRunning = 1;
static void signal_handler(int signum)
{
	gRunning = 0;
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount);

#ifdef __APPLE__
#define iphdr ip
#endif

static void *source_pcap_raw_cb(void *userContext, const struct pcap_pkthdr *hdr, const u_char *pkt)
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

static struct ltntstools_source_pcap_callbacks_s pcap_callbacks = 
{
    .raw = (ltntstools_source_pcap_raw_callback)source_pcap_raw_cb,
};

static void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct input_pid_s *ptr = (struct input_pid_s *)userContext;
	struct tool_ctx_s *ctx = ptr->ctx;

	/* Cache the last video pts */
	ptr->lastVideoPTS = pes->PTS;

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
	printf("  -J 1 (pretty) | 1 (compressed) Output SCTE35 trigger in additional JSON format [def: 0].\n");
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
			if (ctx->pids[pidnr].payloadType == PT_SCTE35) {
				printf("PID %04x : ", pidnr);
				for (int i = 0; i < 188; i++)
					printf("%02x ", buf[j + i]);
				printf("\n");
			}
		}
	}

	/* Detect any scte35 pids if non were set */
	if (ctx->sm == NULL && countPidsByPayloadType(ctx, PT_SCTE35) == 0) {
		if (ltntstools_streammodel_alloc(&ctx->sm, NULL) < 0) {
			fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
			exit(1);
		}
	}

	if (ctx->sm && ctx->smcomplete == 0 && countPidsByPayloadType(ctx, PT_SCTE35) == 0) {
        struct timeval nowtv;
        gettimeofday(&nowtv, NULL);
		ltntstools_streammodel_write(ctx->sm, &buf[0], byteCount / 188, &ctx->smcomplete, &nowtv);

		if (ctx->smcomplete) {
			struct ltntstools_pat_s *pat = NULL;
			if (ltntstools_streammodel_query_model(ctx->sm, &pat) == 0) {

				/* Walk all the services, find the first service with a SCTE35 service.
				 * Query video and SCTE pid.
				 */
				int e = 0;
				struct ltntstools_pmt_s *pmt;
				uint16_t *scte35pids;
				int scte35pid_count = 0;
				while (ltntstools_pat_enum_services_scte35(pat, &e, &pmt, &scte35pids, &scte35pid_count) == 0) {
					for (int i = 0; i < scte35pid_count; i++) {
						setPidType(ctx, scte35pids[i], PT_SCTE35);

						/* Get the associated Video pid */
						uint8_t estype;
						uint16_t videopid;
						if (ltntstools_pmt_query_video_pid(pmt, &videopid, &estype) < 0)
							continue;

						setPidType(ctx, videopid, PT_VIDEO);
						ctx->pids[ scte35pids[i] ].videoPid = videopid;

						printf("Found %s program %5d, scte35 pid 0x%04x (%d), video pid 0x%04x (%d)\n",
							ltntstools_streammodel_is_model_mpts(ctx->sm, pat) ? "MPTS" : "SPTS",
							pmt->program_number,
							scte35pids[i], scte35pids[i],
							ctx->pids[ scte35pids[i] ].videoPid, ctx->pids[ scte35pids[i] ].videoPid);

					}

				}

				//ltntstools_pat_dprintf(pat, STDOUT_FILENO);
				ltntstools_pat_free(pat);
			}
		}
	}

	/* for each scte35/video stream, allocate an extractor */
	for (int i = 0; i < ctx->totalOrderedPids; i++) {
		struct input_pid_s *p = ctx->pidsOrdered[i];

		if (ctx->pids[p->pid].payloadType == PT_SCTE35) {

			/* Setup a section extractor for any found scte pids, if not previously allocated, */
			if (ctx->pids[p->pid].pid && ctx->pids[p->pid].se == NULL) {
				if (ltntstools_sectionextractor_alloc(&ctx->pids[p->pid].se, ctx->pids[p->pid].pid, 0xFC /* SCTE35 Table ID */) < 0) {
					fprintf(stderr, "\nUnable to allocate sectionextractor object.\n\n");
					exit(1);
				}
			}
		} else
		if (ctx->pids[p->pid].payloadType == PT_VIDEO) {

			if (ctx->pids[p->pid].pid && ctx->pids[p->pid].pe == NULL) {
				/* Setup a section extractor for any found scte pids, if not previously allocated, */
				if (ltntstools_pes_extractor_alloc(&ctx->pids[p->pid].pe, ctx->pids[p->pid].pid, 0xe0,
					(pes_extractor_callback)pe_callback, &ctx->pids[p->pid], (1024 * 1024), (1024 * 1024)) < 0)
				{
					fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
					exit(1);
				}
				ltntstools_pes_extractor_set_skip_data(ctx->pids[p->pid].pe, 1);
			}
		}

	}

	for (int i = 0; i < ctx->totalOrderedPids; i++) {
		struct input_pid_s *p = ctx->pidsOrdered[i];

		if (ctx->pids[p->pid].pe) {
			ltntstools_pes_extractor_write(ctx->pids[p->pid].pe, &buf[0], byteCount / 188);
		}

		int secomplete = 0;
		int crcValid = 0;
		if (ctx->pids[p->pid].se) {
			ltntstools_sectionextractor_write(ctx->pids[p->pid].se, &buf[0], byteCount / 188, &secomplete, &crcValid);
		}

		if (secomplete && crcValid == 0) { 
				printf("<-- Trigger %d --------------------------------------------------->\n", ++ctx->pids[p->pid].SCTEMessageCount);
				time_t now = time(0);
				printf("SCTE35 message with invalid CRC (skipped), on pid 0x%04x (%d) @ %s",
					ctx->pids[p->pid].pid,
					ctx->pids[p->pid].pid,
					ctime(&now));
		} else
		if (secomplete && crcValid) {
			unsigned char dst[1024];
			memset(dst, 0, sizeof(dst));
			int len = ltntstools_sectionextractor_query(ctx->pids[p->pid].se, &dst[0], sizeof(dst));
			if (len > 0) {

				printf("<-- Trigger %d --------------------------------------------------->\n", ++ctx->pids[p->pid].SCTEMessageCount);

				time_t now = time(0);
				printf("SCTE35 message on pid 0x%04x (%d) @ %s",
					ctx->pids[p->pid].pid,
					ctx->pids[p->pid].pid,
					ctime(&now));
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

				uint16_t relatedVideoPid = ctx->pids[p->pid].videoPid;
				if (ctx->pids[relatedVideoPid].pe && ctx->pids[relatedVideoPid].lastVideoPTS) {

					char *t = NULL;
					ltntstools_pts_to_ascii(&t, ctx->pids[relatedVideoPid].lastVideoPTS);

					printf("Video pid 0x%04x (%d) last pts %" PRIi64 " [ %s ]\n\n",
						ctx->pids[relatedVideoPid].pid,
						ctx->pids[relatedVideoPid].pid,
						ctx->pids[relatedVideoPid].lastVideoPTS,
						t);

					if (t)
						free(t);
				} else {
					/* Should never happen */
					printf("No PE found on pid 0x%04x\n", relatedVideoPid);
					dumpPids(ctx);
				}

				struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(dst, len);
				if (s) {
					/* Dump struct to console */
					if (ctx->pids[p->pid].pid && ctx->pids[p->pid].lastVideoPTS) {
						s->user_current_video_pts = ctx->pids[p->pid].lastVideoPTS;
					}

					char *json;
					uint16_t byteCount;
					if (ctx->outputJSON && scte35_create_json_message(s, &json, &byteCount, ctx->outputJSON == 1 ? 0 : 1) == 0) {
						printf("%s\n", json);
						free(json);
					}
	
					scte35_splice_info_section_print(s);
					scte35_splice_info_section_free(s);
					printf("\n");
					fflush(0);
				} else {
					printf("SCTE35 trigger %d did not parse reliably, skipping.\n\n", ctx->pids[p->pid].SCTEMessageCount);
					fflush(0);
				}
			}
		}
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

int scte35_inspector(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Unable to allocate memory for application context, aborting.\n");
		return -1;
	}

	ctx->verbose = 1;
	ctx->mode = MODE_SOURCE_AVIO;

	int ch;
	int pid;

	while ((ch = getopt(argc, argv, "?hvi:J:F:P:V:")) != -1) {
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
		case 'J':
			ctx->outputJSON = atoi(optarg);
			if (ctx->outputJSON < 0) {
				ctx->outputJSON = 0;
			} else 
			if (ctx->outputJSON > 2) {
				ctx->outputJSON = 2;
			} else 
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &pid) != 1) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			setPidType(ctx, pid, PT_SCTE35);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'V':
			if ((sscanf(optarg, "0x%x", &pid) != 1) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			setPidType(ctx, pid, PT_VIDEO);
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
		if (ctx->pids[i].pe) {
			ltntstools_pes_extractor_free(ctx->pids[i].pe);
		}
		if (ctx->pids[i].se) {
			ltntstools_sectionextractor_free(ctx->pids[i].se);
		}
	}
	
	if (ctx->sm) {
		ltntstools_streammodel_free(ctx->sm);
	}

	if (ctx->iname) {
		free(ctx->iname);
	}
	
	free(ctx);

	return 0;
}


