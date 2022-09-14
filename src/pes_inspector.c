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

struct nal_throughput_s
{
	time_t    lastReport;
	void     *throughputCtx; /* precise throughput framework handle */
	int64_t   bps;           /* Entire NAL stream bps */

// 31 Nals in H.264
// 63 Nals in H.265
#define MAX_NALS 63
	struct nal_statistic_s stats[MAX_NALS];
};

static void nal_throughput_init(struct nal_throughput_s *ctx)
{
	throughput_hires_alloc(&ctx->throughputCtx, 5000);

	for (int i = 0; i < MAX_NALS; i++) {
		throughput_hires_alloc(&ctx->stats[i].throughputCtx, 2000);
	}
}

static void nal_throughput_free(struct nal_throughput_s *ctx)
{
	throughput_hires_free(ctx->throughputCtx);

	for (int i = 0; i < MAX_NALS; i++) {
		throughput_hires_free(ctx->stats[i].throughputCtx);
	}
}

static void nal_throughput_report(struct nal_throughput_s *ctx, time_t now, int doH264NalThroughput, int doH265NalThroughput)
{
	printf("UnitType                                               Name   Mb/ps  Count @ %s",
		ctime(&now));

	int64_t summed_bps = 0;

	for (int i = 0; i < MAX_NALS; i++) {
		struct nal_statistic_s *nt = &ctx->stats[i]; 
		if (!nt->enabled)
			continue;

		summed_bps += nt->bps;

		const char *nalName = "";
		if (doH264NalThroughput) {
			nalName = h264Nals_lookupName(i);
		} else
		if (doH265NalThroughput) {
			nalName = h265Nals_lookupName(i);
		}
		printf("    0x%02x %50s %7.03f  %"PRIu64 "\n",
			i,
			nalName,
			(double)nt->bps / (double)1e6,
			nt->totalCount);

	}
	printf("--------                                                    %7.03f  Mb/ps\n", (double)summed_bps / (double)1e6);
}

struct tool_ctx_s
{
	int doH264NalThroughput;
	int doH265NalThroughput;
	int verbose;
	int pid;
	int streamId;
	void *pe;
	int writeES;
	uint64_t esSeqNr;

	struct nal_throughput_s throughput;
};

static void _pes_packet_measure_nal_throughput(struct tool_ctx_s *ctx, struct ltn_pes_packet_s *pes, struct nal_throughput_s *s)
{
	struct nal_statistic_s *prevNal = NULL;

	throughput_hires_write_i64(ctx->throughput.throughputCtx, 0, pes->dataLengthBytes * 8, NULL);

    /* Pes payload may contain zero or more complete H264 nals. */ 
    int offset = -1, lastOffset = 0;
	unsigned int nalType = 0;
	int ret;
#define LOCAL_DEBUG 0
#if LOCAL_DEBUG		
	const char *nalName = NULL;
#endif
    while (1) {
		if (ctx->doH264NalThroughput) {
			ret = ltn_nal_h264_findHeader(pes->data, pes->dataLengthBytes, &offset);
		} else
		if (ctx->doH265NalThroughput) {
			ret = ltn_nal_h265_findHeader(pes->data, pes->dataLengthBytes, &offset);
		}
		if (ret < 0) {
			if (prevNal) {
				throughput_hires_write_i64(prevNal->throughputCtx, 0, (pes->dataLengthBytes - lastOffset) * 8, NULL);
			}
			break;
		}
		if (ctx->doH264NalThroughput) {
	  		nalType = pes->data[offset + 3] & 0x1f;
#if LOCAL_DEBUG		
			nalName = h264Nals_lookupName(nalType);
#endif
		} else
		if (ctx->doH265NalThroughput) {
			nalType = (pes->data[offset + 3] >> 1) & 0x3f;
#if LOCAL_DEBUG		
			nalName = h265Nals_lookupName(nalType);
#endif
		}

#if LOCAL_DEBUG		
        for (int i = 0; i < 5; i++) {
            printf("%02x ", *(pes->data + offset + i));
        }
        printf(": NalType %02x : %s\n", nalType, nalName);
#endif

		struct nal_statistic_s *nt = &ctx->throughput.stats[nalType];
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
	if (now != ctx->throughput.lastReport) {
		ctx->throughput.lastReport = now;

		for (int i = 0; i < MAX_NALS; i++) {
			struct nal_statistic_s *nt = &ctx->throughput.stats[i];
			if (!nt->enabled)
				continue;

			nt->bps = throughput_hires_sumtotal_i64(nt->throughputCtx, 0, NULL, NULL);

			throughput_hires_expire(nt->throughputCtx, NULL);
		}

		ctx->throughput.bps = throughput_hires_sumtotal_i64(ctx->throughput.throughputCtx, 0, NULL, NULL);

		if (ctx->doH264NalThroughput || ctx->doH265NalThroughput) {
			nal_throughput_report(&ctx->throughput, now, ctx->doH264NalThroughput, ctx->doH265NalThroughput);
		}
		throughput_hires_expire(ctx->throughput.throughputCtx, NULL);
	}
}

void *callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	/* If we're analyzing NALs then ONLY do this.... */
	if (ctx->doH264NalThroughput || ctx->doH265NalThroughput) {
		_pes_packet_measure_nal_throughput(ctx, pes, &ctx->throughput);
	} else {
		/* Else, dump all the PES packets */
		ltn_pes_packet_dump(pes, "");
	}

	if (ctx->writeES) {

		int arrayLength = 0;
		struct ltn_nal_headers_s *array = NULL;
		if (ltn_nal_h264_find_headers(pes->data, pes->dataLengthBytes, &array, &arrayLength) == 0) {

			for (int i = 0; i < arrayLength; i++) {
				struct ltn_nal_headers_s *e = array + i;
				char fn[256];
				sprintf(&fn[0], "%014" PRIu64 "-es-pid-%04x-streamId-%02x-nal-%02x-name-%s.bin",
					ctx->esSeqNr++,
					ctx->pid,
					ctx->streamId,
					e->nalType,
					e->nalName);
				printf("Writing %s length %9d bytes\n", fn, e->lengthBytes);
				FILE *fh = fopen(fn, "wb");
				if (fh) {
					fwrite(e->ptr, 1, e->lengthBytes, fh);
					fclose(fh);
				}
			}

			free(array);
		}

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
	printf("  -5 dump H.266 NAL headers (live stream only) and measure per-NAL throughput\n");
	printf("  -E write H.264 PES ES Nals to individual sequences files [def: no]\n");
	printf("     Eg. 00000000046068-es-pid-0064-streamId-e0-nal-06-name-SEI.bin\n"
           "         00000000046067-es-pid-0064-streamId-e0-nal-06-name-SEI.bin\n"
           "         00000000046066-es-pid-0064-streamId-e0-nal-09-name-AUD.bin\n"
           "         00000000046072-es-pid-0064-streamId-e0-nal-08-name-PPS.bin\n"
           "         00000000046071-es-pid-0064-streamId-e0-nal-07-name-SPS.bin\n"
           "         00000000046070-es-pid-0064-streamId-e0-nal-09-name-AUD.bin\n"
           "         00000000046077-es-pid-0064-streamId-e0-nal-05-name-slice_layer_without_partitioning_rbsp IDR.bin\n");

}

int pes_inspector(int argc, char *argv[])
{
	struct tool_ctx_s myctx, *ctx;
	ctx = &myctx;
	memset(ctx, 0, sizeof(*ctx));

	nal_throughput_init(&ctx->throughput);

	ctx->streamId = DEFAULT_STREAMID;
	ctx->pid = DEFAULT_PID;

	int ch;
	char *iname = NULL;
	int headersOnly = 0;

	while ((ch = getopt(argc, argv, "45?EHhvi:P:S:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case '4':
			ctx->doH264NalThroughput = 1;
			ctx->doH265NalThroughput = 0;
			break;
		case '5':
			ctx->doH264NalThroughput = 0;
			ctx->doH265NalThroughput = 1;
			break;
		case 'E':
			ctx->writeES = 1;
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
	nal_throughput_free(&ctx->throughput);

	return 0;
}