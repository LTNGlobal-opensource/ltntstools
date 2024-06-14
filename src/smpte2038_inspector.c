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
#include <ctype.h>
#include <signal.h>

#include <libltntstools/ltntstools.h>
#include <libklvanc/vanc.h>

#include "ffmpeg-includes.h"
#include "source-avio.h"

char *strcasestr(const char *haystack, const char *needle);

struct tool_ctx_s
{
	int   verbose;

	int   smpte2038PID;
	void *pe; /* PesExtractor Context */

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

#define sanitizeWord(word) ((word) & 0xff)
extern void klvanc_dump_packet_console(struct klvanc_context_s *ctx, struct klvanc_packet_header_s *hdr);
static int cb_vanc_all(void *callback_context, struct klvanc_context_s *vanchdl, struct klvanc_packet_header_s *hdr)
{
	printf("hdr->type   = %d\n", hdr->type);
	printf(" ->adf      = 0x%04x/0x%04x/0x%04x\n", hdr->adf[0], hdr->adf[1], hdr->adf[2]);
	printf(" ->did/sdid = 0x%02x / 0x%02x [%s %s] via SDI line %d\n",
		hdr->did,
		hdr->dbnsdid,
		klvanc_didLookupSpecification(hdr->did, hdr->dbnsdid),
		klvanc_didLookupDescription(hdr->did, hdr->dbnsdid),
		hdr->lineNr);

	printf(" ->h_offset = %d\n", hdr->horizontalOffset);
	printf(" ->checksum = 0x%04x (%s)\n", hdr->checksum, hdr->checksumValid ? "VALID" : "INVALID");
	printf(" ->payloadLengthWords = %d\n", hdr->payloadLengthWords);

	printf(" ->payload  = ");
	for (int i = 0; i < hdr->payloadLengthWords; i++)
		printf("%02x ", sanitizeWord(hdr->payload[i]));
	printf("\n");

	printf(" ->payload  = ");
	for (int i = 0; i < hdr->payloadLengthWords; i++) {
		char c = sanitizeWord(hdr->payload[i]);
		printf("%2c ", isprint(c) ? c : '.');
	}
	printf("\n");
//	klvanc_dump_packet_console(vanchdl, hdr);
	return 0;
}

static struct klvanc_callbacks_s vanc_callbacks =
{
        .all = cb_vanc_all,
};

static void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	char ts[64];
	libltntstools_getTimestamp(&ts[0], sizeof(ts), NULL);
	printf("---\nEvent at %s\n", ts);

	if (ctx->verbose >= 2) {
		ltn_pes_packet_dump(pes, "");
	}

	struct klvanc_context_s *vanchdl;
	if (klvanc_context_create(&vanchdl) < 0) {
		fprintf(stderr, "Error initializing klvanc library context\n");
		exit(1);
	}
	vanchdl->verbose = 0;
	vanchdl->callbacks = &vanc_callbacks;

	/* The SMPTE2038 KLVANC framework wants a complete PES in a buffer.
	 * pack this pes back into a buffer and hand it to the underlying framework for parsing.
	 */

	/* Copde lifted from klvanc_smpte2038.c - Kernel Labs. */
	/* Parse the PES section, like any other tool might. */
	struct klvanc_smpte2038_anc_data_packet_s *pkt = 0;
	klvanc_smpte2038_parse_pes_packet(pes->rawBuffer, pes->rawBufferLengthBytes, &pkt);
	if (pkt) {
		/* Dump the entire message in english to console, handy for debugging. */
		//klvanc_smpte2038_anc_data_packet_dump(pkt);

		/* For fun, convert all SMPTE2038 ANC Lines into raw VANC, then parse
         * it using the standard VANC library facilities.
         */
		printf("SMPTE2038 message has %d line(s), displaying...\n", pkt->lineCount);
		for (int i = 0; i < pkt->lineCount; i++) {
			struct klvanc_smpte2038_anc_data_line_s *l = &pkt->lines[i];

			uint16_t *words;
			uint16_t wordCount;
			if (klvanc_smpte2038_convert_line_to_words(l, &words, &wordCount) < 0)
					break;

			if (ctx->verbose > 1) {
					printf("LineEntry[%d]: ", i);
					for (int j = 0; j < wordCount; j++)
							printf("%03x ", words[j]);
					printf("\n\n");
			}

			/* Heck, why don't we attempt to parse the vanc? */
			if (klvanc_packet_parse(vanchdl, l->line_number, words, wordCount) < 0) {
			}

			free(words); /* Caller must free the resource */

			//ctx->vanc_packets_found++;
		}

		/* Don't forget to free the parsed SMPTE2038 packet */
		klvanc_smpte2038_anc_data_packet_free(pkt);
	} else {
		fprintf(stderr, "Error parsing vanc packet\n");
	}

	ltn_pes_packet_free(pes);
	klvanc_context_destroy(vanchdl);
	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to display the SMPTE2038 packets from a file, live UDP socket stream, or PCAP NIC.\n");
	printf("Usage:\n");
	printf("  -i <url | nicname>   Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n");
    printf("                           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("                       Eg: eno2    (Also see -F)\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -P 0xnnnn PID containing the SMPTE2038 messages (Optional)\n");
	printf("  -F exact pcap filter. Eg 'host 227.1.20.80 && udp port 4001'\n");
	printf("     DON'T PASS A FILTER WITH MPTS or something with multiple different streams - be very specific, one stream one program\n");
	printf("\nExample:\n");
	printf("  sudo ./tstools_smpte2038_inspector -i eno2 -F 'host 227.1.20.80 && udp port 4001'  -- auto-detect SMPTE pid from nic\n");
	printf("       ./tstools_smpte2038_inspector -i recording.ts                                 -- auto-detect SMPTE pid from file\n");
	printf("       ./tstools_smpte2038_inspector -i recording.ts -P 0x67                         -- Disable auto-detect force decode of pid 0x67\n");
	printf("       ./tstools_smpte2038_inspector -i udp://227.1.20.80:4001                       -- auto-detect SMPTE pid from socket/stream\n");
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount)
{
	if (ctx->verbose >= 2) {
		for (int j = 0; j < byteCount; j += 188) {
			uint16_t pidnr = ltntstools_pid(buf + j);
			if (pidnr == ctx->smpte2038PID) {
				for (int i = 0; i < 188; i++)
					printf("%02x ", buf[j + i]);
				printf("\n");
			}
		}
	}

	if (ctx->sm == NULL && ctx->smpte2038PID == 0) {
		if (ltntstools_streammodel_alloc(&ctx->sm, NULL) < 0) {
			fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
			exit(1);
		}
	}

	if (ctx->sm && ctx->smcomplete == 0 && ctx->smpte2038PID == 0) {
		ltntstools_streammodel_write(ctx->sm, &buf[0], byteCount / 188, &ctx->smcomplete);

		if (ctx->smcomplete) {
			struct ltntstools_pat_s *pat = NULL;
			if (ltntstools_streammodel_query_model(ctx->sm, &pat) == 0) {

				/* Walk all the services, find the first service with a SMPTE2038 service.
				 * Query SMPTE2038 pid.
				 */
				int e = 0;
				struct ltntstools_pmt_s *pmt;
				uint16_t smpte2038pid = 0;
				while (ltntstools_pat_enum_services_smpte2038(pat, &e, &pmt, &smpte2038pid) == 0) {

					uint8_t estype;
					uint16_t videopid;
					if (ltntstools_pmt_query_video_pid(pmt, &videopid, &estype) < 0)
						continue;

					printf("DEBUG: Found program %5d, smpte2038 pid 0x%04x, video pid 0x%04x\n",
						pmt->program_number,
						smpte2038pid,
						videopid);

					ctx->smpte2038PID = smpte2038pid;
					break; /* TODO: We only support the first SCTE35 pid (SPTS) */
				}

				if (ctx->verbose > 1) {
					ltntstools_pat_dprintf(pat, 0);
				}

				if (smpte2038pid == 0) {
					printf("\nNo SMPTE2038 PID detected, terminating\n\n");
					signal_handler(0); /* Terminate */
					//ltntstools_pat_dprintf(pat, 0);
				}
				ltntstools_pat_free(pat);
			}
		}
	}

	if (ctx->smpte2038PID && ctx->pe == NULL) {
		if (ltntstools_pes_extractor_alloc(&ctx->pe, ctx->smpte2038PID, 0xBD,
				(pes_extractor_callback)pe_callback, ctx) < 0) {
			fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
			exit(1);
		}
		ltntstools_pes_extractor_set_skip_data(ctx->pe, 0);
	}

	if (ctx->pe) {
		ltntstools_pes_extractor_write(ctx->pe, &buf[0], byteCount / 188);
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

int smpte2038_inspector(int argc, char *argv[])
{
	struct tool_ctx_s s_ctx = { 0 };
	struct tool_ctx_s *ctx = &s_ctx;
	ctx->verbose = 1;
	ctx->mode = MODE_SOURCE_AVIO;

	int ch;

	while ((ch = getopt(argc, argv, "?hvi:F:P:")) != -1) {
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
			if ((sscanf(optarg, "0x%x", &ctx->smpte2038PID) != 1) || (ctx->smpte2038PID > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
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

	if (ctx->pe) {
		ltntstools_pes_extractor_free(ctx->pe);
	}

	if (ctx->sm) {
		ltntstools_streammodel_free(ctx->sm);
	}

	return 0;
}
