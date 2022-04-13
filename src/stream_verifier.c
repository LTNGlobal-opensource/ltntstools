/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

/* Increase your max socket send buffers for
 * higher throughputs.
 * sysctl -w net.core.wmem_max=2097152
 * */

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"

#define DEFAULT_TOTAL_SECONDS 30
#define DEFAULT_BPS (20 * 1000000)

static uint8_t pat[] = {
	0x47, 0x40, 0x00, 0x17, 0x00, 0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x01, 0xe0,
	0x30, 0xee, 0xd2, 0xf2, 0x31, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff 
};

static uint8_t pmt[] = {
	0x47, 0x40, 0x30, 0x18, 0x00, 0x02, 0xb0,   24, 0x00, 0x01, 0xc1, 0x00, 0x00, 0xe0, 0x31, 0xf0,
	0x06, 0xa2, 0x04, 0x02, 0x00, 0x00, 0x01, 0x86, 0xe0, 0x32, 0xf0, 0x00, 0xe0, 0x31, 0xb7, 0x18,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

struct tool_context_s
{
	int verbose;
	char *iname;
	char *ofn;
	int totalSeconds;
	int bps;

	AVIOContext *puc;
	AVIOContext *o_puc;

	void *smoother;

	unsigned char sendBuffer[7 * 188];
	int sendIndex;
	int minSendBytes;

	/* PCR related */
	uint64_t bitsTransmitted;
	uint64_t pcrLast;
};

static void *callback_smoother(void *userContext, unsigned char *buf, int byteCount)
{
	struct tool_context_s *ctx = userContext;

	avio_write(ctx->o_puc, buf, byteCount);

	return NULL;
}

uint64_t getPCR(struct tool_context_s *ctx, int additionalBits)
{
	//return ctx->pcrLast + ((((double)ctx->bitsTransmitted +
	return ((((double)ctx->bitsTransmitted +
		(double)additionalBits) / (double)ctx->bps) * (double)27000000);
}

static void output_file(struct tool_context_s *ctx, uint8_t *buf, int byteCount, FILE *fh)
{
	ctx->bitsTransmitted += (byteCount * 8);
	fwrite(buf, 1, byteCount, fh);
}

/* Group TS packets into multiples of N, typically 7 * 188 */
/* TODO: Push all of this into the libtstools library so I don't have to keep re-implementing it. */
static void output_write(struct tool_context_s *ctx, const unsigned char *buf, unsigned int byteCount)
{
	ctx->bitsTransmitted += (byteCount * 8);

	if (ctx->minSendBytes == 0) {
		smoother_pcr_write(ctx->smoother, buf, byteCount, NULL);
	} else {
		int len = byteCount;
		int offset = 0;
		int cplen;
		while (len > 0) {
			if (len > (ctx->minSendBytes - ctx->sendIndex)) {
				cplen = ctx->minSendBytes - ctx->sendIndex;
			} else {
				cplen = len;
			}
			memcpy(ctx->sendBuffer + ctx->sendIndex, buf + offset, cplen);
			ctx->sendIndex += cplen;
			offset += cplen;
			len -= cplen;

			if (ctx->sendIndex == ctx->minSendBytes) {
				smoother_pcr_write(ctx->smoother, ctx->sendBuffer, ctx->minSendBytes, NULL);
				ctx->sendIndex = 0;
			}
		}
	}
}

static void usage(const char *progname)
{
	printf("\nA tool to create SPTS streams containing counters, PCRs, PAT and PMT.\n");
	printf("Outputfile can be pushed through any ISO13818 workflow for more intricate loss detection.\n");
	printf("The workflow output can then be routed back into the verifier to check for any bit errors.\n");
	printf("\nOut to file is useful if you want to validate loss-less third-party playout.\n");
	printf("\nUsage:\n");
	printf("  -o <output.ts> | <udp://url>\n");
	printf("  -i <url> Eg: udp://234.1.1.1:4160?localaddr=172.16.0.67\n");
	printf("           172.16.0.67 is the IP addr where we'll issue a IGMP join\n");
	printf("  -v Increase level of verbosity\n");
	printf("  -b <bps> output bitrate [def: %d]\n", DEFAULT_BPS);
	printf("  -d <#seconds> length of output file to create [def: %d]\n", DEFAULT_TOTAL_SECONDS);
	printf("\n    Examples:\n");
	printf("      ./tstools_stream_verifier -o udp://227.1.20.45:4700 -b 20000000 -d 3600\n");
	printf("      ./tstools_stream_verifier -i udp://227.1.20.45:4700\n");
}

int stream_verifier(int argc, char *argv[])
{
#if 0
	uint32_t crc = 0;
	ltntstools_getCRC32(pmt + 5, 23, &crc);
	printf("%08x\n", crc);
	exit(0);
#endif
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->totalSeconds = DEFAULT_TOTAL_SECONDS;
	ctx->bps = DEFAULT_BPS;
	ctx->minSendBytes = 1316;

        while ((ch = getopt(argc, argv, "?hi:b:d:o:v")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
		case 'b':
			ctx->bps = atoi(optarg);
			break;
		case 'd':
			ctx->totalSeconds = atoi(optarg);
			break;
		case 'i':
			ctx->iname = strdup(optarg);
			break;
		case 'o':
			ctx->ofn = strdup(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (!ctx->iname && !ctx->ofn) {
		usage(argv[0]);
		printf("\n");
		printf("-i or -o are mandatory, aborting.\n\n");
		exit(1);
	}

	int pps = ctx->bps / 8 / 188;
	int pcrPeriodMs = 20;
	int pcrsPerSecond = 1000 / pcrPeriodMs;
	int packetsPerPCR = pps / pcrsPerSecond;

	packetsPerPCR -= 2; /* We'll pull a PAT and PMT out after each PCR */

	if (ctx->verbose) {
		printf("totalSeconds  %d\n", ctx->totalSeconds);
		printf("pcrsPerSecond %d\n", pcrsPerSecond);
		printf("packetsPerPCR %d\n", packetsPerPCR);
		printf("pcrPeriodMs   %d\n", pcrPeriodMs);
	}

	avformat_network_init();

	if (ctx->ofn && strncasecmp(ctx->ofn, "udp:", 4) == 0) {
		int ret = smoother_pcr_alloc(&ctx->smoother, ctx, (smoother_pcr_output_callback)callback_smoother, 15000, ctx->minSendBytes, 0x31, ctx->bps);

		ret = avio_open2(&ctx->o_puc, ctx->ofn, AVIO_FLAG_WRITE | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
		if (ret < 0) {
			fprintf(stderr, "-o syntax error\n");
			exit(1);
		}

		uint64_t counter = 0; 
		uint64_t pcr = 0;
		uint8_t pcrcc = 0, countercc = 0, patcc = 0, pmtcc = 0;
		uint8_t pkt[188];

		int t = ctx->totalSeconds;

		while (t-- > 0) { /* Per second */
			int x = pcrsPerSecond;
			while (x-- > 0) {

				pcr = getPCR(ctx, 0);

				int ret = ltntstools_generatePCROnlyPacket(pkt, sizeof(pkt), 0x31, &pcrcc, pcr);
				if (ret < 0)
					break;
				ctx->pcrLast = pcr;

				output_write(ctx, pkt, sizeof(pkt));

				pat[3] = (pat[3] & 0xf0) | (patcc++ & 0x0f);
				output_write(ctx, pat, sizeof(pat));

				pmt[3] = (pmt[3] & 0xf0) | (pmtcc++ & 0x0f);
				output_write(ctx, pmt, sizeof(pmt));

				int i = 0;
				while (i++ < packetsPerPCR) {
					ret  = ltntstools_generatePacketWith64bCounter(pkt, sizeof(pkt), 0x32,
						&countercc, counter++);
					if (ret < 0)
						break;

					output_write(ctx, pkt, sizeof(pkt));
				}
			}
			/* Sleep for a while, otherwise we generate 30 seconds of content in a ms or two,
			 * and we just exhaust the smoother buffers, let's just sleep for something close to
			 * a second, plus allow some time for all of the computation above.
			 * Approximate is ok.
			 */
			usleep(900 * 1000);

		}
		smoother_pcr_free(ctx->smoother);
		avio_close(ctx->o_puc);
	} else if (ctx->ofn) {
		/* Assume file output */
		FILE *ofh = fopen(ctx->ofn, "wb");
		if (ofh) {
			uint64_t counter = 0; 
			uint64_t pcr = 0;
			uint8_t pcrcc = 0, countercc = 0, patcc = 0, pmtcc = 0;
			uint8_t pkt[188];

			int t = ctx->totalSeconds;
			while (t-- > 0) {
				int x = pcrsPerSecond;
				while (x-- > 0) {

					int ret = ltntstools_generatePCROnlyPacket(pkt, sizeof(pkt), 0x31, &pcrcc, pcr);
					if (ret < 0)
						break;
					ctx->pcrLast = pcr;

					output_file(ctx, pkt, sizeof(pkt), ofh);

					pcr += (pcrPeriodMs * 27000);

					pat[3] = (pat[3] & 0xf0) | (patcc++ & 0x0f);
					output_file(ctx, pat, sizeof(pat), ofh);

					pmt[3] = (pmt[3] & 0xf0) | (pmtcc++ & 0x0f);
					output_file(ctx, pmt, sizeof(pmt), ofh);

					int i = 0;
					while (i++ < packetsPerPCR) {
						ret  = ltntstools_generatePacketWith64bCounter(pkt, sizeof(pkt), 0x32,
							&countercc, counter++);
						if (ret < 0)
							break;

						output_file(ctx, pkt, sizeof(pkt), ofh);
					}
				}				
			}
			fclose(ofh);
		}
	}

	if (ctx->iname) {
		printf("Working ....\n");
		int ret = avio_open2(&ctx->puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
		if (ret != 0) {
			fprintf(stderr, "\nError, unable to open input, aborting.\n");
			exit(1);
		}

		int blen = 7 * 188;
		uint8_t *buf = malloc(blen);
		int running = 1;
		uint64_t reads = 0;
		uint64_t lastCounter = 0;
		uint64_t currentCounter = 0;
		uint64_t badMatches = 0;
		while(running) {
			int rlen = avio_read(ctx->puc, buf, blen);
			if (ctx->verbose == 2) {
				printf("source received %d bytes\n", rlen);
			}
			if ((rlen == -EAGAIN) || (rlen == -ETIMEDOUT)) {
				usleep(2 * 1000);
				continue;
			} else
			if (rlen < 0) {
				usleep(2 * 1000);
				running = 0;
				/* General Error or end of stream. */
				continue;
			}

			for (int i = 0; i < rlen; i += 188) {
				uint8_t *pkt = &buf[i];
				if (ltntstools_pid(pkt) != 0x32)
					continue;

				int ret = ltntstools_verifyPacketWith64bCounter(pkt, 188, 0x32, lastCounter, &currentCounter);
				if (reads++ == 0 && ret < 0)
					ret = 0;

				printf("\r%"PRIu64, currentCounter);

				if (ret != 0) {
					badMatches++;
					printf("\rExpected %" PRIu64 " found %"PRIu64 ", %" PRIu64 " bad packets\n", lastCounter, currentCounter, badMatches);
				}
				lastCounter = currentCounter;
			}
		} /* while */
		avio_close(ctx->puc);
		free(buf);

		if (badMatches == 0) {
			printf("\nDone. Success, no errors found in %" PRIu64 " transport packets.\n", reads);
		} else {
			printf("\nDone. Error, %"PRIu64 " error(s) found in %" PRIu64 " transport packets.\n", badMatches, reads);
		}
	}

	if (ctx->ofn)
		free(ctx->ofn);
	if (ctx->iname)
		free(ctx->iname);

	return 0;
}
