/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>
#include "udp.h"
#include "url.h"

#define DEFAULT_FIFOSIZE 1048576

static int gRunning = 0;

struct tool_context_s
{
	struct iso13818_udp_receiver_s *udprx;
	struct url_opts_s *url;
	int verbose;

	FILE *ofh;

	uint64_t bytesWritten;
};

static void *packet_cb(struct tool_context_s *ctx, unsigned char *buf, int byteCount)
{
	size_t wlen = fwrite(buf, 1, byteCount, ctx->ofh);
	ctx->bytesWritten += wlen;

	if (wlen != byteCount) {
		fprintf(stderr, "Warning: unable to write output\n");
	}

	if (ctx->verbose) {
		for (int i = 0; i < byteCount; i += 188) {
			for (int j = 0; j < 16; j++) {
				printf("%02x ", buf[i + j]);
				if (j == 3)
					printf("-- ");
			}
			printf("\n");
		}
	}

	return 0;
}

static void signal_handler(int signum)
{
	gRunning = 0;
}

static void usage(const char *progname)
{
	printf("A tool to capture ISO13818 TS packet from the UDP network.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://234.1.1.1:5000?ifname=eno1\n");
	printf("  -o <output filename>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int udp_capture(int argc, char *argv[])
{
	int ret = 0;
	int ch;
	char *iname = NULL;
	char *oname = NULL;
	int fifosize = DEFAULT_FIFOSIZE;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

	while ((ch = getopt(argc, argv, "?hi:o:v")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			if (url_parse(optarg, &ctx->url) < 0) {
				fprintf(stderr, "Problem parsing url, aborting.\n");
				exit(1);
			}
			iname = optarg;
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'o':
			oname = optarg;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (iname == NULL) {
		fprintf(stderr, "-i is mandatory.\n");
		exit(1);
	}
	if (oname == NULL) {
		fprintf(stderr, "-o is mandatory.\n");
		exit(1);
	}

	ctx->ofh = fopen(oname, "wb");
	if (!ctx->ofh) {
		fprintf(stderr, "Problem opening output file, aborting.\n");
		ret = -1;
		goto no_output;
	}

	if (ctx->url->has_fifosize)
		fifosize = ctx->url->fifosize;

	ret = iso13818_udp_receiver_alloc(&ctx->udprx, fifosize, ctx->url->hostname, ctx->url->port,
		(tsudp_receiver_callback)packet_cb, ctx, 0);
	if (ret < 0) {
		fprintf(stderr, "Problem allocating the URL receiver, aborting.\n");
		ret = -1;
		goto no_udp;
	}

	if (ctx->url->has_ifname)
		iso13818_udp_receiver_join_multicast(ctx->udprx, ctx->url->ifname);

	ret = iso13818_udp_receiver_thread_start(ctx->udprx);
	if (ret < 0) {
		fprintf(stderr, "Problem allocating the UDP receiver thread, aborting.\n");
		ret = -1;
		goto no_thread;
	}

	signal(SIGINT, signal_handler);
	gRunning = 1;
	while (gRunning) {
		usleep(50 * 1000);
	}
	ret = 0;

	printf("\nWrote %" PRIu64 " bytes to %s\n", ctx->bytesWritten, oname);

no_thread:
	if (ctx->udprx)
		iso13818_udp_receiver_free(&ctx->udprx);

no_udp:
	if (ctx->url)
		url_free(ctx->url);

	fclose(ctx->ofh);

no_output:
	return ret;
}
