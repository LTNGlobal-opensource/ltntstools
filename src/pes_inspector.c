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

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"

#define DEFAULT_STREAMID 0xe0
#define DEFAULT_PID 0x31

struct tool_ctx_s
{
	int verbose;
	int pid;
	int streamId;
	void *pe;
};

void *callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	ltn_pes_packet_dump(pes, "");
	ltn_pes_packet_free(pes);

	return NULL;
}

static void usage(const char *progname)
{
	printf("\nA tool to extract and display PES packets from transport files or streams.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
               "           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -P 0xnnnn PID containing the program elementary stream [def: 0x%02x]\n", DEFAULT_PID);
	printf("  -S PES Stream Id. Eg. 0xe0 or 0xc0 [def: 0x%02x]\n", DEFAULT_STREAMID);
}

int pes_inspector(int argc, char *argv[])
{
	struct tool_ctx_s myctx, *ctx;
	ctx = &myctx;
	memset(ctx, 0, sizeof(*ctx));

	ctx->streamId = DEFAULT_STREAMID;
	ctx->pid = DEFAULT_PID;

	int ch;
	char *iname = NULL;

	while ((ch = getopt(argc, argv, "?hvi:P:S:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			iname = optarg;
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &ctx->pid) != 1) || (ctx->pid > 0x1fff)) {
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
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->pid == 0) {
		usage(argv[0]);
		fprintf(stderr, "\n-P is mandatory.\n\n");
		exit(1);
	}

	if (iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	if (ltntstools_pes_extractor_alloc(&ctx->pe, ctx->pid, ctx->streamId,
			(pes_extractor_callback)callback, NULL) < 0) {
		fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
		exit(1);
	}
	
	ltntstools_pes_extractor_set_skip_data(ctx->pe, ctx->verbose ? 0 : 1);

	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	uint8_t buf[7 * 188];
	int ok = 1;
	while (ok) {
		int rlen = avio_read(puc, &buf[0], sizeof(buf));
		if (rlen == -EAGAIN) {
			usleep(2 * 1000);
			continue;
		}
		if (rlen < 0)
			break;

		ltntstools_pes_extractor_write(ctx->pe, &buf[0], rlen / 188);

	}
	avio_close(puc);

	ltntstools_pes_extractor_free(ctx->pe);

	return 0;
}


