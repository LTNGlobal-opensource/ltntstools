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

struct nal_statistic_s
{
	int       enabled;       /* Boolean. */
	uint64_t  totalCount;    /* Number of messages received for this specific NAL */
	int64_t   bps;           /* Per NAL throughput bps */
	void     *throughputCtx; /* precise throughput framework handle */
};

struct nal_h264_throughput_s
{
	time_t    lastReport;
	void     *throughputCtx; /* precise throughput framework handle */
	int64_t   bps;           /* Entire NAL stream bps */

#define MAX_NALS 32
	struct nal_statistic_s stats[MAX_NALS];
};

static void nal_h264_throughput_init(struct nal_h264_throughput_s *ctx)
{
	throughput_hires_alloc(&ctx->throughputCtx, 5000);

	for (int i = 0; i < MAX_NALS; i++) {
		throughput_hires_alloc(&ctx->stats[i].throughputCtx, 2000);
	}
}

static void nal_h264_throughput_free(struct nal_h264_throughput_s *ctx)
{
	throughput_hires_free(ctx->throughputCtx);

	for (int i = 0; i < MAX_NALS; i++) {
		throughput_hires_free(ctx->stats[i].throughputCtx);
	}
}

static void nal_h264_throughput_report(struct nal_h264_throughput_s *ctx, time_t now)
{
	printf("UnitType                                                Name  Mb/ps  Count @ %s",
		ctime(&now));

	int64_t summed_bps = 0;

	for (int i = 0; i < MAX_NALS; i++) {
		struct nal_statistic_s *nt = &ctx->stats[i]; 
		if (!nt->enabled)
			continue;

		summed_bps += nt->bps;

		printf("    0x%02x %50s %7.03f  %"PRIu64 "\n",
			i,
			h264Nals_lookupName(i),
			(double)nt->bps / (double)1e6,
			nt->totalCount);

	}
	printf("--------                                                    %7.03f  Mb/ps\n", (double)summed_bps / (double)1e6);
}

struct tool_ctx_s
{
	int doH264NalThroughput;
	int verbose;
	int pid;
	int streamId;
	void *pe;

	struct nal_h264_throughput_s h264_throughput;
};

static void _pes_packet_measure_nal_h264_throughput(struct tool_ctx_s *ctx, struct ltn_pes_packet_s *pes, struct nal_h264_throughput_s *s)
{
	struct nal_statistic_s *prevNal = NULL;

	throughput_hires_write_i64(ctx->h264_throughput.throughputCtx, 0, pes->dataLengthBytes * 8, NULL);

    /* Pes payload may contain zero or more complete H264 nals. */ 
    int offset = -1, lastOffset = 0;
    while (1) {
        int ret = ltn_nal_h264_findHeader(pes->data, pes->dataLengthBytes, &offset);
        if (ret < 0) {
			if (prevNal) {
		   		throughput_hires_write_i64(prevNal->throughputCtx, 0, (pes->dataLengthBytes - lastOffset) * 8, NULL);
			}
           break;
        }

  		unsigned int nalType = pes->data[offset + 3] & 0x1f;
#define LOCAL_DEBUG 0

#if LOCAL_DEBUG
		const char *nalName = h264Nals_lookupName(nalType);

        for (int i = 0; i < 5; i++) {
            printf("%02x ", *(pes->data + offset + i));
        }
        printf(": NalType %02x : %s\n", nalType, nalName);
#endif

		struct nal_statistic_s *nt = &ctx->h264_throughput.stats[nalType];
		nt->enabled = 1;
		nt->totalCount++;

		if (!prevNal) {
			prevNal = nt;
			continue;
		}

		/* On a per NAL basis, maintain a throughput */
		throughput_hires_write_i64(prevNal->throughputCtx, 0, (offset - lastOffset) * 8, NULL);
	
		lastOffset = offset;
		prevNal = nt;
	}

	/* Summary report once per second */
	time_t now = time(NULL);
	if (now != ctx->h264_throughput.lastReport) {
		ctx->h264_throughput.lastReport = now;

		for (int i = 0; i < MAX_NALS; i++) {
			struct nal_statistic_s *nt = &ctx->h264_throughput.stats[i];
			if (!nt->enabled)
				continue;

			nt->bps = throughput_hires_sumtotal_i64(nt->throughputCtx, 0, NULL, NULL);

			throughput_hires_expire(nt->throughputCtx, NULL);
		}

		ctx->h264_throughput.bps = throughput_hires_sumtotal_i64(ctx->h264_throughput.throughputCtx, 0, NULL, NULL);

		nal_h264_throughput_report(&ctx->h264_throughput, now);
		throughput_hires_expire(ctx->h264_throughput.throughputCtx, NULL);
	}
}

void *callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	/* If we're analyzing NALs then ONLY do this.... */
	if (ctx->doH264NalThroughput) {
		_pes_packet_measure_nal_h264_throughput(ctx, pes, &ctx->h264_throughput);
	} else {
		/* Else, dump all the PES packets */
		ltn_pes_packet_dump(pes, "");
	}

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
	printf("  -H Show PES headers only, don't parse payload. [def: disabled, payload shown]\n");
	printf("  -4 dump H.264 NAL headers (live stream only) and measure per-NAL throughput\n");
}

int pes_inspector(int argc, char *argv[])
{
	struct tool_ctx_s myctx, *ctx;
	ctx = &myctx;
	memset(ctx, 0, sizeof(*ctx));

	nal_h264_throughput_init(&ctx->h264_throughput);

	ctx->streamId = DEFAULT_STREAMID;
	ctx->pid = DEFAULT_PID;

	int ch;
	char *iname = NULL;
	int headersOnly = 0;

	while ((ch = getopt(argc, argv, "4?Hhvi:P:S:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case '4':
			ctx->doH264NalThroughput = 1;
			break;
		case 'H':
			headersOnly = 1;
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
			(pes_extractor_callback)callback, ctx) < 0) {
		fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
		exit(1);
	}
	
	ltntstools_pes_extractor_set_skip_data(ctx->pe, headersOnly);

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
	nal_h264_throughput_free(&ctx->h264_throughput);

	return 0;
}


