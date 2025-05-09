/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>

#include "dump.h"
#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"

#define LOCAL_DEBUG 0

char *strcasestr(const char *haystack, const char *needle);

struct tool_ctx_s
{
	int  verbose;
	void *trhdl;

#define MODE_SOURCE_AVIO 0
#define MODE_SOURCE_PCAP 1
	int mode;

	int isRTP;

	void *src_pcap; /* Source-pcap context */
	char *iname;
	char *pcap_filter;

};

static int gRunning = 1;
static void signal_handler(int signum)
{
	gRunning = 0;
}

void *cb_notify(void *userContext, struct ltntstools_tr101290_alarm_s *array, int count)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

#if LOCAL_DEBUG
	printf("%s(%p, %d)\n", __func__, array, count);
#endif

	for (int i = 0; i < count; i++) {
		struct ltntstools_tr101290_alarm_s *ae = &array[i];
		ltntstools_tr101290_event_dprintf(STDOUT_FILENO, ae);
	}

	free((struct ltntstools_tr101290_alarm_s *)array);

	/* For fun, collect the entire summary in txt format. */
	if (ctx->verbose > 1) {
		ltntstools_tr101290_summary_report_dprintf(ctx->trhdl, STDOUT_FILENO);
	}

	return NULL;
}

static void process_transport_buffer(struct tool_ctx_s *ctx, const unsigned char *buf, int byteCount)
{
	if (ctx->verbose > 2) {
		printf("tr101290 sending %d bytes\n", byteCount);
	}

        struct timeval nowtv;
        gettimeofday(&nowtv, NULL);

	ssize_t s = ltntstools_tr101290_write(ctx->trhdl, buf, byteCount / 188, &nowtv);
	if (s) { }
}

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
			if (ctx->verbose > 2) {

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

static struct ltntstools_source_pcap_callbacks_s pcap_callbacks = 
{
    .raw = (ltntstools_source_pcap_raw_callback)source_pcap_raw_cb,
};

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
	if (ctx->verbose > 2) {
		printf("AVIO packet %d bytes\n", packetCount * 188);
	}
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

static void usage(const char *progname)
{
	printf("A tool to collect transport packets from UDP and feed them into the TR101290 analyzer, reporting stream issues.\n");
	printf("Usage:\n");
	printf("  -i <url | nicname>   Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n");
    printf("                           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("                       Eg: eno2    (Also see -F)\n");
	printf("     DON'T PASS A FILTER WITH MPTS or something with multiple different streams - be very specific, one stream one program\n");
	printf("  -F exact pcap filter. Eg 'host 227.1.20.80 && udp port 4001'\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("\nExample:\n");
	printf("  sudo ./tstools_tr101290_analyzer -i eno2 -F 'host 227.1.20.80 && udp port 4001'\n");
	printf("       ./tstools_tr101290_analyzer -i udp://227.1.20.80:4001\n");
}

int tr101290_analyzer(int argc, char *argv[])
{
	int ch;
	struct tool_ctx_s sctx, *ctx = &sctx;
	memset(ctx, 0, sizeof(*ctx));

	ctx->mode = MODE_SOURCE_AVIO;

	while ((ch = getopt(argc, argv, "?hvi:F:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'F':
			ctx->pcap_filter = strdup(optarg);
			ctx->mode = MODE_SOURCE_PCAP;
			break;
		case 'i':
			ctx->iname = strdup(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->iname == NULL) {
		fprintf(stderr, "-i is mandatory.\n");
		exit(1);
	}

	if (getuid() == 0 && getenv("SUDO_UID") && getenv("SUDO_GID") && ctx->mode != MODE_SOURCE_PCAP) {
		usage(argv[0]);
		fprintf(stderr, "\n**** Don't use SUDO against file or udp socket sources, ONLY nic/pcap sources ****.\n\n");
		exit(1);
	}

	ltntstools_tr101290_alloc(&ctx->trhdl, (ltntstools_tr101290_notification)cb_notify, ctx);

	signal(SIGINT, signal_handler);

	if (ctx->mode == MODE_SOURCE_AVIO) {
		printf("Mode: AVIO\n");
		process_avio_input(ctx);
	} else
	if (ctx->mode == MODE_SOURCE_PCAP) {
		printf("Mode: PCAP\n");
		process_pcap_input(ctx);
	}

	ltntstools_tr101290_free(ctx->trhdl);
	free(ctx->iname);

	return 0;
}
