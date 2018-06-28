#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "klbitstream_readwriter.h"
#include "ts.h"

struct pid_s
{
	uint64_t scr_first;
	time_t   scr_first_time;
	uint64_t scr;
	uint64_t updateCount;
};

struct tool_context_s
{
	const char *fn;
	FILE *fh;
	time_t initial_time;
	uint32_t pid;
	struct pid_s pids[8192];
};

static void usage(const char *progname)
{
	printf("A tool to extract/process PTS/PCR clocks from a MPEGTS file.\n");
	printf("Usage:\n");
	printf("  -i <filename>\n");
	printf("  -P 0xN <pid>\n");
	printf("  -T YYYYMMDDHHMMSS [def: current time]\n");
}

int clock_inspector(int argc, char *argv[])
{
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

        while ((ch = getopt(argc, argv, "?hi:P:T:")) != -1) {
		switch (ch) {
		case 'i':
			ctx->fn = optarg;
			break;
		case 'P':
			if (sscanf(optarg, "0x%x", &ctx->pid) != 1) {
				usage(argv[0]);
				fprintf(stderr, "-P invalid PID\n");
				exit(1);
			}
			break;
		case 'T':
			{
				//time_t mktime(struct tm *tm);
				struct tm tm = { 0 };
				if (sscanf(optarg, "%04d%02d%02d%02d%02d%02d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
					&tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
				{
					usage(argv[0]);
					fprintf(stderr, "-T invalid datetime\n");
					exit(1);
				}
				tm.tm_year -= 1900;
				tm.tm_mon -= 1;
				ctx->initial_time = mktime(&tm);
				printf("initial_time = %d\n", ctx->initial_time);
			}
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->initial_time == 0) {
		time(&ctx->initial_time);
	}

	if (ctx->fn == 0) {
		fprintf(stderr, "-i is mandatory\n");
		exit(1);
	}

	/* File is assumed to have properly aligned packets. */
	ctx->fh = fopen(ctx->fn, "rb");
	if (!ctx->fh) {
		fprintf(stderr, "Unable to open file '%s'\n", ctx->fn);
		exit(1);
	}

	int max_packets = 32;
	uint8_t *buf = malloc(188 * max_packets);
	if (!buf) {
		fclose(ctx->fh);
		fprintf(stderr, "Unable to allocate buffer\n");
		exit(1);
	}

	int linenr = 0;
	while (!feof(ctx->fh)) {
		size_t rlen = fread(buf, 188, max_packets, ctx->fh);
		if (rlen <= 0)
			break;

		for (int i = 0; i < rlen; i++) {

			uint8_t *p = buf + (i * 188);
			uint16_t pid = ltn_iso13818_pid(p);
			if (ctx->pid && pid != ctx->pid)
				continue;

			uint64_t scr;
			if (ltn_iso13818_scr(p, &scr) < 0)
				continue;

			uint64_t scr_diff = 0;
			if (ctx->pids[pid].updateCount > 0)
				scr_diff = scr - ctx->pids[pid].scr;
			else {
				ctx->pids[pid].scr_first = scr;
				ctx->pids[pid].scr_first_time = ctx->initial_time;
			}

			ctx->pids[pid].scr = scr;

			if (linenr++ == 0) {
				printf("+filepos ------------>                   SCR  <--- SCR-DIFF ----->     UPDATE  \n");
				printf("+    Hex           Dec   PID       27MHz VAL       TICKS        uS      COUNT\n");
			}

			if (linenr > 24)
				linenr = 0;

			time_t dt = ctx->pids[pid].scr_first_time;
			dt += ((scr - ctx->pids[pid].scr_first) / 27000000);

			char str[64];
			sprintf(str, "%s", ctime(&dt));
			str[ strlen(str) - 1] = 0;

			ctx->pids[pid].updateCount++;
			printf("%08" PRIx64 " %13" PRIu64 "  %04x  %14" PRIu64 "  %10" PRIu64 "  %8" PRIu64 "  %9" PRIu64 "  %s\n",
				(ftell(ctx->fh) - (188 * rlen)) + (i * 188),
				(ftell(ctx->fh) - (188 * rlen)) + (i * 188),
				pid,
				scr,
				scr_diff,
				scr_diff / 27,
				ctx->pids[pid].updateCount,
				str);
			
		}
	}

	free(buf);
	fclose(ctx->fh);
	return 0;
}
