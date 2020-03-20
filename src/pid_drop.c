/* For a given TS file, drop N packets on PID X start at PID X packet Y. */
/* A tool that should take a clean video file, drop PTS packets for a specific pid a reproduce the TR101290 2.5 error on demand. */

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "klbitstream_readwriter.h"
#include <libltntstools/ltntstools.h>

struct tool_context_s
{
	const char *ifn, *ofn;
	FILE *ifh, *ofh;

	unsigned int pid;
	unsigned int doFixups;
	uint16_t pidDropping;
	uint16_t pidCCFixups;
	uint32_t pidPacketReadCount;
	uint32_t pidPacketDropCount;
	uint32_t pidPacketDropPosition;
	uint32_t pidPacketsDropped;
	uint8_t pidLastCC;

	uint64_t ts_total_packets;
};

static void usage(const char *progname)
{
	printf("A tool to drop packets from an ISO13818 MPEGTS file, by pid.\n");
	printf("Input file is assumed to be properly packet aligned.\n");
	printf("Usage:\n");
	printf("  -i <input.ts>\n");
	printf("  -o <output.ts>\n");
	printf("  -f enable fixup the CC counters in the headers after dropping [def: disabled]\n");
	printf("  -P pid 0xNNNN to be removed [def: 0x0]\n");
	printf("  -p <number>. Drop packets from packet <number> onwards, for -n packets. [def: 0x0]\n");
	printf("  -n <number>. NUmber of packets to drop on pid -P. [def: 0x0]\n");
}

int pid_drop(int argc, char *argv[])
{
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

        while ((ch = getopt(argc, argv, "?fhi:n:o:p:P:")) != -1) {
		switch (ch) {
		case 'f':
			ctx->doFixups = 1;
			break;
		case 'n':
			ctx->pidPacketDropCount = atoi(optarg);
			break;
		case 'i':
			ctx->ifn = optarg;
			break;
		case 'o':
			ctx->ofn = optarg;
			break;
		case 'p':
			ctx->pidPacketDropPosition = atoi(optarg);
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &ctx->pid) != 1) || (ctx->pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->ifn == 0) {
		fprintf(stderr, "-i is mandatory\n");
		exit(1);
	}
	if (ctx->ofn == 0) {
		fprintf(stderr, "-o is mandatory\n");
		exit(1);
	}

	/* File is assumed to have properly aligned packets. */
	ctx->ifh = fopen(ctx->ifn, "rb");
	if (!ctx->ifh) {
		fprintf(stderr, "Unable to open input file '%s'\n", ctx->ifn);
		exit(1);
	}

	ctx->ofh = fopen(ctx->ofn, "wb");
	if (!ctx->ofh) {
		fprintf(stderr, "Unable to open output file '%s'\n", ctx->ofn);
		fclose(ctx->ifh);
		exit(1);
	}

	int max_packets = 32;
	uint8_t *buf = malloc(188 * max_packets);
	if (!buf) {
		fclose(ctx->ofh);
		fclose(ctx->ifh);
		fprintf(stderr, "Unable to allocate buffer\n");
		exit(1);
	}

	printf("Dropping %d packets on pid 0x%04x starting at packet #%d, %s correct CC in headers\n",
		ctx->pidPacketDropCount, ctx->pid, ctx->pidPacketDropPosition,
		ctx->doFixups ? "will" : "WILL NOT");

	while (!feof(ctx->ifh)) {
		size_t rlen = fread(buf, 188, max_packets, ctx->ifh);
		if (rlen <= 0)
			break;

		for (int i = 0; i < rlen; i++) {

			uint8_t *p = buf + (i * 188);
			ctx->ts_total_packets++;

			uint16_t pid = ltntstools_pid(p);
			if (ctx->pid != pid) {
				fwrite(p, 1, 188, ctx->ofh);
				continue;
			}

			ctx->pidPacketReadCount++;

			if (ctx->pidPacketReadCount == ctx->pidPacketDropPosition) {
				/* Start dropping packets. */
				ctx->pidDropping = 1;
				ctx->pidPacketsDropped = 0;
			}

			if (ctx->pidPacketsDropped == ctx->pidPacketDropCount) {
				ctx->pidDropping = 0;
				ctx->pidCCFixups = 1;
			}

			if (ctx->pidDropping)
				ctx->pidPacketsDropped++;
			else {
				if (ctx->doFixups && ctx->pidCCFixups) {
					uint32_t afc = ltntstools_adaption_field_control(p);
					if ((afc == 1) || (afc == 3)) {
						*(p + 3) &= 0xf0;
						*(p + 3) |= ((ctx->pidLastCC + 1) & 0x0f);
					}
				}
				fwrite(p, 1, 188, ctx->ofh);
				ctx->pidLastCC = ltntstools_continuity_counter(p);
			}
		}
	}

	free(buf);

	fclose(ctx->ofh);
	fclose(ctx->ifh);
	return 0;
}
