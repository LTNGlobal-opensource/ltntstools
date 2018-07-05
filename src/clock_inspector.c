#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "klbitstream_readwriter.h"
#include "ts.h"
#include "pes.h"
#include "hexdump.h"

struct pid_s
{
	uint64_t scr_first;
	time_t   scr_first_time;
	uint64_t scr;
	uint64_t updateCount;
	uint32_t cc;

	uint64_t pts_count;
	struct ltn_pes_packet_s pts_last;
	int64_t pts_diff_ticks;

	uint64_t dts_count;
	struct ltn_pes_packet_s dts_last;
	int64_t dts_diff_ticks;

	struct ltn_pes_packet_s pes;
};

struct tool_context_s
{
	int dumpHex;
	const char *fn;
	FILE *fh;
	time_t initial_time;
	time_t current_stream_time;
	uint32_t pid;
	struct pid_s pids[8192];
};

static ssize_t processPESHeader(uint8_t *buf, uint32_t lengthBytes, uint32_t pid, struct tool_context_s *ctx)
{
	struct pid_s *p = &ctx->pids[pid];
	if (p->pes.PTS_DTS_flags == 2) {
		ltn_pes_packet_copy(&p->pts_last, &p->pes);
	} else
	if (p->pes.PTS_DTS_flags == 3) {
		ltn_pes_packet_copy(&p->pts_last, &p->pes);
		ltn_pes_packet_copy(&p->dts_last, &p->pes);
	}

	struct klbs_context_s pbs, *bs = &pbs;
	klbs_init(bs);
	klbs_read_set_buffer(bs, buf, lengthBytes);

	ssize_t len = ltn_pes_packet_parse(&p->pes, bs);

	if (p->pes.PTS_DTS_flags == 2) {
		p->pts_diff_ticks = p->pes.PTS - p->pts_last.PTS;
		p->pts_count++;
	} else
	if (p->pes.PTS_DTS_flags == 3) {
		p->pts_diff_ticks = p->pes.PTS - p->pts_last.PTS;
		p->pts_count++;
		p->dts_diff_ticks = p->pes.DTS - p->dts_last.DTS;
		p->dts_count++;
	}

	if (len > 0) {
		ltn_pes_packet_dump(&p->pes);
	}

	if (p->pes.PTS_DTS_flags == 2) {
		printf("PTS #%09" PRIi64 " -- %04x  diff %7" PRIi64 "(ticks)  %5" PRIi64 "(ms)\n", p->pts_count, pid, p->pts_diff_ticks,
			PTS_TICKS_TO_MS(p->pts_diff_ticks));
	}
	if (p->pes.PTS_DTS_flags == 3) {
		printf("PTS #%09" PRIi64 " -- %04x  diff %7" PRIi64 "(ticks)  %5" PRIi64 "(ms)\n", p->pts_count, pid, p->pts_diff_ticks,
			PTS_TICKS_TO_MS(p->pts_diff_ticks));
		printf("DTS #%09" PRIi64 " -- %04x  diff %7" PRIi64 "(ticks)  %5" PRIi64 "(ms)\n", p->dts_count, pid, p->dts_diff_ticks,
			PTS_TICKS_TO_MS(p->dts_diff_ticks));
	}

	return len;
}

static void usage(const char *progname)
{
	printf("A tool to extract/process PTS/PCR clocks from a MPEGTS file.\n");
	printf("Usage:\n");
	printf("  -i <filename>\n");
	printf("  -P 0xN <pid>\n");
	printf("  -T YYYYMMDDHHMMSS [def: current time]\n");
	printf("  -d Dump every ts packet header in hex to console (3x -d entire packet)\n");
}

int clock_inspector(int argc, char *argv[])
{
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

        while ((ch = getopt(argc, argv, "?dhi:P:T:")) != -1) {
		switch (ch) {
		case 'd':
			ctx->dumpHex++;
			break;
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
			int peshdr = ltn_iso13818_payload_unit_start_indicator(p);

			int pesoffset = 0;
			if (peshdr) {
				pesoffset = ltn_iso13818_contains_pes_header(p + 4, 188 - 4);
			}


			if (ctx->dumpHex) {

				for (int j = 0; j < 4; j++) {
					printf("%02x ", *(p + j));
				}
				printf("-- %04x %s", pid,
					peshdr ? "PESHDR" : "      ");
				printf("\n");
				if (peshdr && pesoffset >= 0) {
					printf("            -- ");
					hexdump(p + 4 + pesoffset, 12, 32);
				}
			}
			if (ctx->dumpHex == 2) {
				hexdump(p, 32, 32 + 1); /* +1 avoid additional trailing CR */
			} else
			if (ctx->dumpHex == 3) {
				hexdump(p, 188, 32);
			}

			if (peshdr && pesoffset >= 0 && pid > 0) {
				processPESHeader(p + 4 + pesoffset, 188 - 4 - pesoffset, pid, ctx);
				printf("\n");
			}

			if (ctx->pid && pid != ctx->pid)
				continue;
#if 0
			for (int j = 0; j < 8; j++) {
				printf("%02x ", *(p + j));
			}
			printf("\n");
#endif
			uint32_t cc = ltn_iso13818_continuity_counter(p);

			uint32_t afc = ltn_iso13818_adaption_field_control(p);
			if ((afc == 1) || (afc == 3)) {
				if (ctx->pids[pid].updateCount > 0) {
					if (((ctx->pids[pid].cc + 1) & 0x0f) != cc) {
						char str[64];
						sprintf(str, "%s", ctime(&ctx->current_stream_time));
						str[ strlen(str) - 1] = 0;
						printf("CC Error. PID %04x expected %02x got %02x @ %s\n",
							pid, (ctx->pids[pid].cc + 1) & 0x0f, cc, str);
					}
				}
			}
			ctx->pids[pid].cc = cc;

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

			ctx->current_stream_time = dt;

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
