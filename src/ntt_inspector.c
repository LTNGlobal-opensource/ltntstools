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
#include <time.h>

#include <libltntstools/ltntstools.h>
#include <libklvanc/vanc.h>
#include "libntt/ntt.h"

#include "ffmpeg-includes.h"

struct tool_ctx_s
{
	int   verbose;

	int   smpte2038PID;
	void *pe; /* PesExtractor Context */

	void *src_pcap; /* Source-pcap context */
	char *iname;
	char *pcap_filter;

	void *sm; /* StreamModel Context */
	int smcomplete;
	int show_timecodes;

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;

	struct tissot_context *tissot_ctx;
	int last_report_time;

	/* For decoding S12-2 timecodes */
	struct klvanc_context_s *vanchdl;
};

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
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->uh_sport));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udphdr->uh_dport));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				
				src, dst,
				ntohs(udphdr->uh_ulen),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		int lengthPayloadBytes = ntohs(udphdr->uh_ulen) - sizeof(struct udphdr);
		
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

static void parse_evertzserial(struct tool_ctx_s *ctx, const uint8_t *buf, int data_count)
{
    /* Evertz Model 7721de4 serial embedders have a standard four-byte header
       on all VANC packets.  The first byte (0x18) is static, and the other
       three bytes indicate serial parameters such as baud rate, stop bits, etc */

    if (data_count < 4) {
        printf("Invalid Evertz packet (length=%d)\n", data_count);
        return;
    }

    /*
      Byte 0: always 0x18
      Byte 1: target serial port number (0-3)
      Byte 2: baud rate, parity, data bits
      Byte 3: bitmask of currently active GPI pins
    */
    if (buf[0] != 0x18) {
        /* This is not a valid Evertz 7721DE4 VANC packet */
        printf("Invalid Evertz packet %02x %02x %02x %02x\n",
               buf[0], buf[1], buf[2], buf[3]);
        return;
    }

    if ((buf[1] & 0x03) != 0x00) {
        /* We only care about packets intended for the specified serial port.
           Ignore data intended for other ports... */
        return;
    }

    if (data_count == 4) {
        /* No payload, so no need to continue */
        return;
    }

    tissot_parse_serial(ctx->tissot_ctx, buf + 4, data_count - 4);
}

#define sanitizeWord(word) ((word) & 0xff)

static int cb_SMPTE_12_2(void *callback_context, struct klvanc_context_s *ctx,
			 struct klvanc_packet_smpte_12_2_s *pkt)
{
	printf("{ \"smpte_timecode\" : \"%02d:%02d:%02d:%02d\" }\n", pkt->hours, pkt->minutes,
               pkt->seconds, pkt->frames);
	return 0;
}

static struct klvanc_callbacks_s vanc_callbacks =
{
	.smpte_12_2	= cb_SMPTE_12_2,
};

static void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	char ts[64];
	libltntstools_getTimestamp(&ts[0], sizeof(ts), NULL);
	//printf("---\nEvent at %s\n", ts);

	if (ctx->verbose >= 2) {
		ltn_pes_packet_dump(pes, "");
	}

	/* Parse the PES section, like any other tool might. */
	struct klvanc_smpte2038_anc_data_packet_s *pkt = 0;
	klvanc_smpte2038_parse_pes_packet(pes->rawBuffer, pes->rawBufferLengthBytes, &pkt);
	if (pkt) {
		/* Dump the entire message in english to console, handy for debugging. */
		//klvanc_smpte2038_anc_data_packet_dump(pkt);

		//printf("SMPTE2038 message has %d line(s), displaying...\n", pkt->lineCount);
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

			if (sanitizeWord(l->DID) == 0x50 && sanitizeWord(l->SDID) == 0x01) {
				int data_count = sanitizeWord(l->data_count);
				uint8_t buf[255];
				for (int j = 0; j < data_count; j++)
					buf[j] = sanitizeWord(l->user_data_words[j]);
				parse_evertzserial(ctx, buf, data_count);
			}

			if (ctx->show_timecodes && klvanc_packet_parse(ctx->vanchdl, l->line_number, words, wordCount) < 0) {
				fprintf(stderr, "Failed to parse the packet\n");
			}

			free(words); /* Caller must free the resource */
		}

		/* Don't forget to free the parsed SMPTE2038 packet */
		klvanc_smpte2038_anc_data_packet_free(pkt);
	} else {
		fprintf(stderr, "Error parsing vanc packet\n");
	}

	ltn_pes_packet_free(pes);

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to display NBA Tissot Timing packets from a file, live UDP socket stream, or PCAP NIC.\n");
	printf("Usage:\n");
	printf("  -i <url | nicname>   Eg: udp://227.1.20.45:4001?localaddr=192.168.20.45\n");
    printf("                           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("                       Eg: eno2    (Also see -F)\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -P 0xnnnn PID containing the SMPTE2038 messages (Optional)\n");
	printf("  -t Show SMPTE 12-2 timecodes if found in SMPTE 2038 stream\n");
	printf("  -F exact pcap filter. Eg 'host 227.1.20.80 && udp port 4001'\n");
	printf("     DON'T PASS A FILTER WITH MPTS or something with multiple different streams - be very specific, one stream one program\n");
	printf("\nExample:\n");
	printf("  sudo ./tstools_ntt_inspector -i eno2 -F 'host 227.1.20.80 && udp port 4001'  -- auto-detect SMPTE pid from nic\n");
	printf("       ./tstools_ntt_inspector -i recording.ts                                 -- auto-detect SMPTE pid from file\n");
	printf("       ./tstools_ntt_inspector -i recording.ts -P 0x67                         -- Disable auto-detect force decode of pid 0x67\n");
	printf("       ./tstools_ntt_inspector -i udp://227.1.20.80:4001                       -- auto-detect SMPTE pid from socket/stream\n");
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
					break; /* TODO: We only support ehf first SCTE35 pid (SPTS) */
				}

				if (ctx->verbose > 1) {
					ltntstools_pat_dprintf(pat, 0);
				}

				if (smpte2038pid == 0) {
					printf("\nNo SMPTE2038 PID detected\n\n");
					ltntstools_pat_dprintf(pat, 0);
				}
				ltntstools_pat_free(pat);
			}
			if (ctx->smpte2038PID == 0) {
				/* Free up the stream model so we can detect 2038 in the PMT if it
				   starts appearing */
				ltntstools_streammodel_free(ctx->sm);
				ctx->sm = NULL;
				ctx->smcomplete = 0;
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

	int ok = 1;
	while (ok) {
		time_t cur_time = time(NULL);
		if (cur_time > ctx->last_report_time) {
			char *json_stats = tissot_stats_recent_json(ctx->tissot_ctx);
			if (json_stats != NULL) {
				printf("%s\n", json_stats);
				fflush(stdout);
				free(json_stats);
			}
			ctx->last_report_time = cur_time;
		}

		usleep(50 * 1000);
	}

	ltntstools_source_pcap_free(ctx->src_pcap);
}

static void process_avio_input(struct tool_ctx_s *ctx)
{
	avformat_network_init();
	AVIOContext *puc;
	time_t cur_time;

	/* TODO: Migrate this to use the source-avio.[ch] framework */
	int ret = avio_open2(&puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return;
	}

	uint8_t buf[7 * 188];
	int ok = 1;
	while (ok) {
		cur_time = time(NULL);
		if (cur_time > ctx->last_report_time) {
			char *json_stats = tissot_stats_recent_json(ctx->tissot_ctx);
			if (json_stats != NULL) {
				printf("%s\n", json_stats);
				fflush(stdout);
				free(json_stats);
			}
			ctx->last_report_time = cur_time;
		}

		int rlen = avio_read(puc, &buf[0], sizeof(buf));
		if (rlen == -EAGAIN) {
			usleep(200 * 1000);
			continue;
		}
		if (rlen < 0)
			break;

		process_transport_buffer(ctx, &buf[0], rlen);
	}
	avio_close(puc);

        char *json_stats = tissot_stats_json(ctx->tissot_ctx);
        if (json_stats != NULL) {
            printf("%s\n", json_stats);
            fflush(stdout);
            free(json_stats);
        }
}

static void tissot_log_cb(void *p, int level, const char *fmt, ...)
{
	struct tool_ctx_s *ctx = p;
	/* By default log warning/errors, but they can get info/debug by increasing
	   verbosity level */
	if (ctx->verbose > (level - 2)) {
		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
	}
}

static void tissot_cb(void *user_ctx, const char *json_buf)
{
	printf("%s\n", json_buf);
	fflush(stdout);
}

int ntt_inspector(int argc, char *argv[])
{
	struct tool_ctx_s s_ctx = { 0 };
	struct tool_ctx_s *ctx = &s_ctx;
	ctx->verbose = 1;
	ctx->mode = MODE_SOURCE_AVIO;

	ctx->tissot_ctx = tissot_alloc();
	if (ctx->tissot_ctx == NULL) {
		fprintf(stderr, "Error initializing ntt library context\n");
		exit(1);
	}
	ctx->tissot_ctx->user_ctx = ctx;
	ctx->tissot_ctx->user_cb = tissot_cb;
	ctx->tissot_ctx->log_cb = tissot_log_cb;

	if (klvanc_context_create(&ctx->vanchdl) < 0) {
		fprintf(stderr, "Error initializing klvanc library context\n");
		exit(1);
	}
	ctx->vanchdl->verbose = 0;
	ctx->vanchdl->callbacks = &vanc_callbacks;

	int ch;

	while ((ch = getopt(argc, argv, "?hvti:F:P:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->iname = strdup(optarg);
			break;
		case 't':
			ctx->show_timecodes = 1;
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

	tissot_free(ctx->tissot_ctx);
	klvanc_context_destroy(ctx->vanchdl);

	return 0;
}


