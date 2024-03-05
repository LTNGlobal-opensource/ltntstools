/*
 * The clock inspector extracts and plots differnt clocks from a MPEG-TS stream and
 * performs some lightweight math to measure distances, intervals, timeliness.
 *
 * In file input mode, measurements such as 'walltime drift' or Timestamp often make
 * no sense because the input stream is arriving faster than realtime.
 * 
 * In stream/udp input cases, values such ed 'filepos' make no real sense but instead
 * represents bytes received.
 * 
 * If you ignore small nuances like this, the tool is meaningfull in many ways.
 *
 * When using the -s mode to report PCR timing, it's important that the correct PCR
 * pid value is passed using -S. WIthout this, the PCR is assumed to be on a default pid
 * and some of the SCR reported data will be incorrect, even though most of it gets
 * autotected. **** make sure you have the -S option set of you care about reading
 * the SCR reports.
 * 
 * SCR (PCR) reporting
 * +SCR Timing         filepos ------------>                   SCR  <--- SCR-DIFF ------>  SCR             Walltime ----------------------------->  Drift
 * +SCR Timing             Hex           Dec   PID       27MHz VAL       TICKS         uS  Timecode        Now                      secs               ms
 * SCR #000000003 -- 000056790        354192  0031    959636022118      944813      34993  0.09:52:22.074  Fri Feb  9 09:13:52 2024 1707488033.067      0
 *                                                                       (since last PCR)                 
 */

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>

#include "klbitstream_readwriter.h"
#include <libltntstools/ltntstools.h>
#include "xorg-list.h"
#include "ffmpeg-includes.h"

#define DEFAULT_SCR_PID 0x31

struct ordered_clock_item_s {
	struct xorg_list list;

	uint64_t nr;
	int64_t clock;
	uint64_t filepos;
};

struct pid_s
{
	/* TS packets */
	uint64_t pkt_count;
	uint32_t cc;
	uint64_t cc_errors;

	/* PCR / SCR */
	uint64_t scr_first;
	time_t   scr_first_time;
	uint64_t scr;
	uint64_t scr_updateCount;

	/* PTS */
	uint64_t pts_count;
	struct ltn_pes_packet_s pts_last;
	int64_t pts_diff_ticks;
	uint64_t pts_last_scr; /* When we captured the last packet, this reflects the SCR at the time. */
	struct ltntstools_clock_s clk_pts;
	int clk_pts_initialized;

	/* DTS */
	uint64_t dts_count;
	struct ltn_pes_packet_s dts_last;
	int64_t dts_diff_ticks;
	uint64_t dts_last_scr; /* When we captured the last packet, this reflects the SCR at the time. */
	struct ltntstools_clock_s clk_dts;
	int clk_dts_initialized;

	/* Working data for PTS / DTS */
	struct ltn_pes_packet_s pes;

	struct xorg_list ordered_pts_list;
};

struct tool_context_s
{
	int dumpHex;
	const char *iname;
	time_t initial_time;
	time_t current_stream_time;
	int64_t maxAllowablePTSDTSDrift;
//	uint32_t pid;
	struct pid_s pids[8192];

	int doPacketStatistics;
	int doSCRStatistics;
	int doPESStatistics;
	int pts_linenr;
	int scr_linenr;
	int ts_linenr;

	uint64_t ts_total_packets;

	int order_asc_pts_output;

	int scr_pid;

	struct ltntstools_stream_statistics_s *libstats;
};

static int gRunning = 1;
static void signal_handler(int signum)
{
	gRunning = 0;
}

/* Ordered PTS handling */
static void ordered_clock_init(struct xorg_list *list)
{
	xorg_list_init(list);
}

/* The clock is a PTS 90KHz counter */
static void ordered_clock_insert(struct xorg_list *list, struct ordered_clock_item_s *src)
{
	struct ordered_clock_item_s *e = calloc(1, sizeof(*e));
	memcpy(e, src, sizeof(*src));

	if (xorg_list_is_empty(list)) {
		xorg_list_append(&e->list, list);
		return;
	}

	/* Search the list backwards */
	struct ordered_clock_item_s *item = NULL;
	xorg_list_for_each_entry_reverse(item, list, list) {
		if (src->clock >= item->clock) {
			__xorg_list_add(&e->list, &item->list, item->list.next);
			return;
		}
	}
}

static void ordered_clock_dump(struct xorg_list *list, unsigned short pid)
{
	int64_t last = -1;
	uint64_t diffTicks = 0;

	int linenr = 0;

	struct ordered_clock_item_s *i = NULL, *next = NULL;
	xorg_list_for_each_entry_safe(i, next, list, list) {
		if (last == -1) {
			diffTicks = 0;
		} else {
			diffTicks = ltntstools_pts_diff(last, i->clock);
		}

		if (linenr++ == 24) {
			linenr = 0;
			printf("+PTS/DTS (ordered) filepos ------------>               PTS/DTS  <------- DIFF ------>\n");
			printf("+PTS/DTS #             Hex           Dec   PID       90KHz VAL       TICKS         MS\n");
		}

		printf("PTS #%09" PRIi64 " -- %09" PRIx64 " %13" PRIu64 "  %04x  %14" PRIi64 "  %10" PRIi64 " %10.2f\n",
			i->nr,
			i->filepos,
			i->filepos,
			pid,
			i->clock,
			diffTicks,
			(double)diffTicks / 90);

		last = i->clock;
	}
}

/* End: Ordered PTS handling */

static void pidReport(struct tool_context_s *ctx)
{
	double total = ctx->ts_total_packets;
	for (int i = 0; i <= 0x1fff; i++) {
		if (ctx->pids[i].pkt_count) {
			printf("pid: 0x%04x pkts: %12" PRIu64 " discontinuities: %12" PRIu64 " using: %7.1f%%\n",
				i,
				ctx->pids[i].pkt_count,
				ctx->pids[i].cc_errors,
				((double)ctx->pids[i].pkt_count / total) * 100.0);
		}
	}
}

static ssize_t processPESHeader(uint8_t *buf, uint32_t lengthBytes, uint32_t pid, struct tool_context_s *ctx, uint64_t filepos)
{
	struct pid_s *p = &ctx->pids[pid];
	if ((p->pes.PTS_DTS_flags == 2) || (p->pes.PTS_DTS_flags == 3)) {
		ltn_pes_packet_copy(&p->pts_last, &p->pes);

		if (p->clk_pts_initialized == 0) {
			p->clk_pts_initialized = 1;
			ltntstools_clock_initialize(&p->clk_pts);
			ltntstools_clock_establish_timebase(&p->clk_pts, 90000);
			ltntstools_clock_establish_wallclock(&p->clk_pts, p->pes.PTS);
		}
		ltntstools_clock_set_ticks(&p->clk_pts, p->pes.PTS);
	}
	if (p->pes.PTS_DTS_flags == 3) {
		ltn_pes_packet_copy(&p->dts_last, &p->pes);

		if (p->clk_dts_initialized == 0) {
			p->clk_dts_initialized = 1;
			ltntstools_clock_initialize(&p->clk_dts);
			ltntstools_clock_establish_timebase(&p->clk_dts, 90000);
			ltntstools_clock_establish_wallclock(&p->clk_dts, p->pes.DTS);
		}
		ltntstools_clock_set_ticks(&p->clk_dts, p->pes.DTS);

	}

	struct klbs_context_s pbs, *bs = &pbs;
	klbs_init(bs);
	klbs_read_set_buffer(bs, buf, lengthBytes);

	ssize_t len = ltn_pes_packet_parse(&p->pes, bs, 1 /* SkipDataExtraction */);

	/* Track the difference in SCR clocks between this PTS header and the prior. */
	uint64_t pts_scr_diff_ms = 0;
	uint64_t dts_scr_diff_ms = 0;

	if ((p->pes.PTS_DTS_flags == 2) || (p->pes.PTS_DTS_flags == 3)) {
		p->pts_diff_ticks = ltntstools_pts_diff(p->pts_last.PTS, p->pes.PTS);
		p->pts_count++;
		//p->scr = ctx->pids[ctx->scr_pid].scr;
		pts_scr_diff_ms = ltntstools_scr_diff(p->pts_last_scr, p->scr) / 27000;
		p->pts_last_scr = p->scr;
	}
	if (p->pes.PTS_DTS_flags == 3) {
		p->dts_diff_ticks = ltntstools_pts_diff(p->pts_last.DTS, p->pes.DTS);
		p->dts_count++;
		dts_scr_diff_ms = ltntstools_scr_diff(p->dts_last_scr, p->scr) / 27000;
		p->dts_last_scr = p->scr;
	}

	if (ctx->pts_linenr++ == 0) {
		printf("+PTS/DTS Timing     filepos ------------>               PTS/DTS  <------- DIFF ------> <---- SCR <--PTS*300--------->  Walltime ----------------------------->  Drift\n");
		printf("+PTS/DTS Timing         Hex           Dec   PID       90KHz VAL       TICKS         MS   Diff MS  minus SCR        ms  Now                      secs               ms\n");
	}
	if (ctx->pts_linenr > 24)
		ctx->pts_linenr = 0;

	/* Process a PTS if present. */
	if ((p->pes.PTS_DTS_flags == 2) || (p->pes.PTS_DTS_flags == 3)) {

		int64_t ptsWalltimeDriftMs = 0;
		if (p->clk_pts_initialized) {
			ptsWalltimeDriftMs = ltntstools_clock_get_drift_ms(&p->clk_pts);
		}

		/* Calculate the offset between the PTS and the last good SCR, assumed to be on pid DEFAULR_SCR_PID. */
		int64_t pts_minus_scr_ticks = ltntstools_scr_diff(ctx->pids[ctx->scr_pid].scr, p->pes.PTS * 300);
		double d_pts_minus_scr_ticks = ltntstools_scr_diff(ctx->pids[ctx->scr_pid].scr, p->pes.PTS * 300);
		d_pts_minus_scr_ticks /= 27000;

		if ((PTS_TICKS_TO_MS(p->pts_diff_ticks)) >= ctx->maxAllowablePTSDTSDrift) {
			char str[64];
			sprintf(str, "%s", ctime(&ctx->current_stream_time));
			str[ strlen(str) - 1] = 0;
			printf("!PTS #%09" PRIi64 " Error. Difference between previous and current 90KHz clock >= +-%" PRIi64 "ms (is %" PRIi64 ") @ %s\n",
				p->pts_count,
				ctx->maxAllowablePTSDTSDrift,
				PTS_TICKS_TO_MS(p->pts_diff_ticks),
				str);
		}

		if ((pts_scr_diff_ms) >= ctx->maxAllowablePTSDTSDrift) {
			char str[64];
			sprintf(str, "%s", ctime(&ctx->current_stream_time));
			str[ strlen(str) - 1] = 0;
			printf("!PTS #%09" PRIi64 " Error. Difference between previous and current PTS frame measured in SCR ticks >= +-%" PRIi64 "ms (is %" PRIi64 ") @ %s\n",
				p->pts_count,
				ctx->maxAllowablePTSDTSDrift,
				pts_scr_diff_ms,
				str);
		}

		char time_str[64];
		struct timeval ts;
		gettimeofday(&ts, NULL);

		time_t now = time(NULL);
		sprintf(time_str, "%s", ctime(&now));
		time_str[ strlen(time_str) - 1] = 0;

		if (!ctx->order_asc_pts_output) {
			printf("PTS #%09" PRIi64
				" -- %09" PRIx64
				" %13" PRIu64
				"  %04x  "
				"%14" PRIi64
				"  %10" PRIi64
				" %10.2f %9" PRIi64
				" %10" PRIi64
				" %9.2f  %s %08d.%03d %6" PRIi64 "\n",
				p->pts_count,
				filepos,
				filepos,
				pid,
				p->pes.PTS,
				p->pts_diff_ticks,
				(double)p->pts_diff_ticks / 90,
				pts_scr_diff_ms,
				pts_minus_scr_ticks,
				d_pts_minus_scr_ticks,
				time_str,
				(int)ts.tv_sec,
				(int)ts.tv_usec / 1000,
				ptsWalltimeDriftMs);
		}

		if (ctx->order_asc_pts_output) {
			if (p->pts_count == 1) {
				ordered_clock_init(&p->ordered_pts_list);
			}
			
			struct ordered_clock_item_s item;
			item.nr = p->pts_count;
			item.clock = p->pes.PTS;
			item.filepos = filepos;
			ordered_clock_insert(&p->ordered_pts_list, &item);
		}

	}
	/* Process a DTS if present. */
	if (p->pes.PTS_DTS_flags == 3) {

#if 0
		/* Disabled for now, TODO */
		int64_t dtsWalltimeDriftMs = 0;
		if (p->clk_dts_initialized) {
			dtsWalltimeDriftMs = ltntstools_clock_get_drift_ms(&p->clk_dts);
		}
#endif
		if ((PTS_TICKS_TO_MS(p->dts_diff_ticks)) >= ctx->maxAllowablePTSDTSDrift) {
			char str[64];
			sprintf(str, "%s", ctime(&ctx->current_stream_time));
			str[ strlen(str) - 1] = 0;
			printf("!DTS #%09" PRIi64 " Error. Difference between previous and current 90KHz clock >= +-%" PRIi64 "ms (is %" PRIi64 ") @ %s\n",
				p->dts_count,
				ctx->maxAllowablePTSDTSDrift,
				PTS_TICKS_TO_MS(p->pts_diff_ticks),
				str);
		}

		if ((dts_scr_diff_ms) >= ctx->maxAllowablePTSDTSDrift) {
			char str[64];
			sprintf(str, "%s", ctime(&ctx->current_stream_time));
			str[ strlen(str) - 1] = 0;
			printf("!DTS #%09" PRIi64 " Error. Difference between previous and current DTS frame measured in SCR ticks >= +-%" PRIi64 "ms (is %" PRIi64 ") @ %s\n",
				p->dts_count,
				ctx->maxAllowablePTSDTSDrift,
				dts_scr_diff_ms,
				str);
		}

		printf("DTS #%09" PRIi64 " -- %09" PRIx64 " %13" PRIu64 "  %04x  %14" PRIi64 "  %10" PRIi64 " %10.2f %9" PRIu64 "\n",
			p->dts_count,
			filepos,
			filepos,
			pid,
			p->pes.DTS,
			p->dts_diff_ticks,
			(double)p->dts_diff_ticks / 90, // MMM
			dts_scr_diff_ms);
	}

	if (len > 0 && ctx->doPESStatistics > 1) {
		ltn_pes_packet_dump(&p->pes, "    ");
	}

	return len;
}

static void processSCRStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos)
{
	uint16_t pid = ltntstools_pid(pkt);

	uint64_t scr;
	if (ltntstools_scr(pkt, &scr) < 0)
		return;

	uint64_t scr_diff = 0;
	if (ctx->pids[pid].scr_updateCount > 0) {
		scr_diff = ltntstools_scr_diff(ctx->pids[pid].scr, scr);
	} else {
		ctx->pids[pid].scr_first = scr;
		ctx->pids[pid].scr_first_time = ctx->initial_time;
	}

	ctx->pids[pid].scr = scr;

	if (ctx->scr_linenr++ == 0) {
		printf("+SCR Timing         filepos ------------>                   SCR  <--- SCR-DIFF ------>  SCR             Walltime ----------------------------->  Drift\n");
		printf("+SCR Timing             Hex           Dec   PID       27MHz VAL       TICKS         uS  Timecode        Now                      secs               ms\n");
	}

	if (ctx->scr_linenr > 24)
		ctx->scr_linenr = 0;

	time_t dt = ctx->pids[pid].scr_first_time;
	dt += (ltntstools_scr_diff(ctx->pids[pid].scr_first, scr) / 27000000);

	ctx->current_stream_time = dt;

	char str[64];
	sprintf(str, "%s", ctime(&dt));
	str[ strlen(str) - 1] = 0;

	char *scr_ascii = NULL;
	ltntstools_pcr_to_ascii(&scr_ascii, scr);

	ctx->pids[pid].scr_updateCount++;

	char walltimePCRReport[32] = { 0 };
	int64_t PCRWalltimeDriftMs = 0;
	if (ltntstools_pid_stats_pid_get_pcr_walltime_driftms(ctx->libstats, pid, &PCRWalltimeDriftMs) == 0) {
		sprintf(walltimePCRReport, "%5" PRIi64, PCRWalltimeDriftMs);
	} else {
		sprintf(walltimePCRReport, "    NA");
	}

	struct timeval ts;
	gettimeofday(&ts, NULL);
	printf("SCR #%09" PRIu64 " -- %09" PRIx64 " %13" PRIu64 "  %04x  %14" PRIu64 "  %10" PRIu64 "  %9" PRIu64 "  %s  %s %08d.%03d %6s\n",
		ctx->pids[pid].scr_updateCount,
		filepos,
		filepos,
		pid,
		scr,
		scr_diff,
		scr_diff / 27,
		scr_ascii,
		str,
		(int)ts.tv_sec,
		(int)ts.tv_usec / 1000,
		walltimePCRReport);

	free(scr_ascii);
}

static void processPacketStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos)
{
	uint16_t pid = ltntstools_pid(pkt);
	ctx->pids[pid].pkt_count++;

	uint32_t cc = ltntstools_continuity_counter(pkt);

	if (ctx->dumpHex) {
		if (ctx->ts_linenr++ == 0) {
			printf("+TS Packet         filepos ------------>\n");
			printf("+TS Packet             Hex           Dec   PID  Packet --------------------------------------------------------------------------------------->\n");
		}
		if (ctx->ts_linenr > 24)
			ctx->ts_linenr = 0;

		printf("TS  #%09" PRIu64 " -- %08" PRIx64 " %13" PRIu64 "  %04x  ",
			ctx->ts_total_packets,
			filepos,
			filepos,
			pid);
	}

	if (ctx->dumpHex == 1) {
		ltntstools_hexdump(pkt, 32, 32 + 1); /* +1 avoid additional trailing CR */
	} else
	if (ctx->dumpHex == 2) {
		ltntstools_hexdump(pkt, 188, 32);
	}

	uint32_t afc = ltntstools_adaption_field_control(pkt);
	if ((afc == 1) || (afc == 3)) {
		/* Every pid will be in error the first occurece. Check on second and subsequent pids. */
		if (ctx->pids[pid].pkt_count > 1) {
			if (((ctx->pids[pid].cc + 1) & 0x0f) != cc) {
				/* Don't CC check null pid. */
				if (pid != 0x1fff) {
					char str[64];
					sprintf(str, "%s", ctime(&ctx->current_stream_time));
					str[ strlen(str) - 1] = 0;
					printf("!CC Error. PID %04x expected %02x got %02x @ %s\n",
						pid, (ctx->pids[pid].cc + 1) & 0x0f, cc, str);
					ctx->pids[pid].cc_errors++;
				}
			}
		}
	}
	ctx->pids[pid].cc = cc;
}

static void processPESStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos)
{
	uint16_t pid = ltntstools_pid(pkt);
	int peshdr = ltntstools_payload_unit_start_indicator(pkt);

	int pesoffset = 0;
	if (peshdr) {
		pesoffset = ltntstools_contains_pes_header(pkt + 4, 188 - 4);
	}

	if (peshdr && pesoffset >= 0 && pid > 0) {
		processPESHeader(pkt + 4 + pesoffset, 188 - 4 - pesoffset, pid, ctx, filepos);
	}
}

static int validateClockMath()
{
	/* Setup a PCR */
	struct ltntstools_clock_s pcrclk;

	ltntstools_clock_initialize(&pcrclk);
	ltntstools_clock_establish_timebase(&pcrclk, 27 * 1e6);

	int i = 1;
	while (1) {
		if (ltntstools_clock_is_established_wallclock(&pcrclk) == 0) {
			ltntstools_clock_establish_wallclock(&pcrclk, 1 * 27000000);
		}
		sleep(1);
		i++;
		ltntstools_clock_set_ticks(&pcrclk, (i * (27 * 1e6)) + 2000);
		int64_t us = ltntstools_clock_get_drift_us(&pcrclk);
		printf("drift us: %" PRIi64 "\n", us);
	}

	return 0;
}

static void kernel_check_socket_sizes(AVIOContext *i)
{
	printf("Kernel configured default/max socket buffer sizes:\n");

	char line[256];
	int val;
	FILE *fh = fopen("/proc/sys/net/core/rmem_default", "r");
	if (fh) {
		fread(&line[0], 1, sizeof(line), fh);
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_default = %d\n", val);
		fclose(fh);
	}

	fh = fopen("/proc/sys/net/core/rmem_max", "r");
	if (fh) {
		fread(&line[0], 1, sizeof(line), fh);
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_max = %d\n", val);
		if (i->buffer_size > val) {
			fprintf(stderr, "buffer_size %d exceeds rmem_max %d, aborting\n", i->buffer_size, val);
			exit(1);
		}
		fclose(fh);
	}

}

static void usage(const char *progname)
{
	printf("A tool to extract PCR/SCR PTS/DTS clocks from all pids in a MPEGTS file, or stream.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
		"           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -T YYYYMMDDHHMMSS [def: current time]\n");
	printf("     Time is only relevant when running -s SCR mode. The tool will adjust\n");
	printf("     the initial SCR to match walltime, then any other SCR it reports will\n");
	printf("     be reported as initial walltime plus SCR difference. Useful when\n");
	printf("     trying to match TS files to other logging mechanisms based on datetime\n");
	printf("  -d Dump every ts packet header in hex to console (use additional -d for more detail)\n");
	printf("  -s Dump SCR/PCR time, adjusting for -T initial time if necessary\n");
	printf("  -S <0xpid> Use SCR on this pid. [def: 0x%04x]\n", DEFAULT_SCR_PID);
	printf("  -p Dump PTS/DTS (use additional -p to show PES header on console)\n");
	printf("  -D Max allowable PTS/DTS clock drift value in ms. [def: 700]\n");
	printf("  -R Reorder the PTS display output to be in ascending PTS order [def: disabled]\n");
	printf("     In this case we'll calculate the PTS intervals reliably based on picture frame display order [def: disabled]\n");
	printf("     This mode casuses all PES headers to be cached (growing memory usage over time), it's memory expensive.\n");
	printf("  -P Show progress indicator as a percentage when processing large files [def: disabled]\n");
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
	printf("\n  Example UDP or RTP:\n");
	printf("    tstools_clock_inspector -i 'udp://227.1.20.80:4002?localaddr=192.168.20.45&buffer_size=2500000&overrun_nonfatal=1&fifo_size=50000000' -S 0x31 -p\n");
}

int clock_inspector(int argc, char *argv[])
{
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->doPacketStatistics = 1;
	ctx->doSCRStatistics = 0;
	ctx->doPESStatistics = 0;
	ctx->maxAllowablePTSDTSDrift = 700;
	ctx->scr_pid = DEFAULT_SCR_PID;
	int progressReport = 0;
	int stopSeconds = 0;

	/* We use this specifically for tracking PCR walltime drift */
	ltntstools_pid_stats_alloc(&ctx->libstats);

    while ((ch = getopt(argc, argv, "?dhi:spt:T:D:PRS:X")) != -1) {
		switch (ch) {
		case 'd':
			ctx->dumpHex++;
			break;
		case 'i':
			ctx->iname = optarg;
			break;
		case 'p':
			ctx->doPESStatistics++;
			break;
		case 'P':
			progressReport = 1;
			break;
		case 's':
			ctx->doSCRStatistics = 1;
			break;
		case 'S':
			if ((sscanf(optarg, "0x%x", &ctx->scr_pid) != 1) || (ctx->scr_pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			ltntstools_pid_stats_pid_set_contains_pcr(ctx->libstats, ctx->scr_pid);
			break;
		case 'D':
			ctx->maxAllowablePTSDTSDrift = atoi(optarg);
			break;
		case 'R':
			ctx->order_asc_pts_output = 1;
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
		case 't':
			stopSeconds = atoi(optarg);
			break;
		case 'X':
			return validateClockMath();
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->initial_time == 0) {
		time(&ctx->initial_time);
	}

	if (ctx->iname == 0) {
		usage(argv[0]);
		fprintf(stderr, "\nError, -i is mandatory, aborting\n\n");
		exit(1);
	}

	int blen = 188 * 1024;
	uint8_t *buf = malloc(blen);
	if (!buf) {
		fprintf(stderr, "Unable to allocate buffer\n");
		exit(1);
	}

	uint64_t fileLengthBytes = 0;
	FILE *fh = fopen(ctx->iname, "rb");
	if (fh) {
		fseeko(fh, 0, SEEK_END);
		fileLengthBytes = ftello(fh);
		fclose(fh);
	} else {
		progressReport = 0;
	}

	/* TODO: Replace this with avio so we can support streams. */
	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i error, unable to open file or url\n");
		return 1;
	}

	kernel_check_socket_sizes(puc);

	signal(SIGINT, signal_handler);

	time_t stopTime = time(NULL) + stopSeconds;

	/* TODO: Migrate this to use the source-avio.[ch] framework */
	uint64_t filepos = 0;
	uint64_t streamPosition = 0;
	while (gRunning) {

		if (stopSeconds) {
			time_t now = time(NULL);
			if (now > stopTime) {
				signal_handler(1);
			}
		}

		int rlen = avio_read(puc, buf, blen);
		if (rlen == -EAGAIN) {
			usleep(1 * 1000);
			continue;
		}
		if (rlen < 0)
			break;

		streamPosition += rlen;

		/* Push the entire stream into the stats layer - so we can compyte walltime */
		ltntstools_pid_stats_update(ctx->libstats, buf, rlen / 188);

		for (int i = 0; i < rlen; i += 188) {

			filepos = (streamPosition - rlen) + i;

			uint8_t *p = (buf + i);

			if (ctx->doPacketStatistics) {
				processPacketStats(ctx, p, filepos);
			}

			if (ctx->doSCRStatistics) {
				processSCRStats(ctx, p, filepos);
			}

			if (ctx->doPESStatistics) {
				/* Big caveat here: We expect the PES header to be contained
				 * somewhere (anywhere) in this single packet, and we only parse
				 * enough bytes to extract PTS and DTS.
				 */
				processPESStats(ctx, p, filepos);
			}

			ctx->ts_total_packets++;

		}
		if (progressReport) {
			fprintf(stderr, "\rprocessing ... %.02f%%",
				(double)(((double)filepos / (double)fileLengthBytes) * 100.0));
		}
	}
	avio_close(puc);

	if (progressReport) {
		fprintf(stderr, "\ndone\n");
	}

	printf("\n");
	pidReport(ctx);

	if (ctx->libstats) {
		ltntstools_pid_stats_free(ctx->libstats);
		ctx->libstats = NULL;
	}

	free(buf);

	if (ctx->order_asc_pts_output) {
		for (int i = 0; i <= 0x1fff; i++) {
			if (ctx->pids[i].pts_count > 0) {
				ordered_clock_dump(&ctx->pids[i].ordered_pts_list, i);
			}
		}
	}
	return 0;
}
