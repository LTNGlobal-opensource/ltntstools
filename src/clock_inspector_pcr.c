#include "clock_inspector_public.h"

void processSCRStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts)
{
	uint16_t pid = ltntstools_pid(pkt);

	uint64_t scr;
	if (ltntstools_scr(pkt, &scr) < 0)
		return;

	int64_t stc;
	int r = ltntstools_bitrate_calculator_query_stc(ctx->libstats, &stc);
	if (r == 0 && ctx->verbose) {
		int64_t diff = ltntstools_scr_diff(stc, scr);
		printf("+STC %" PRIi64 " is %10s pcr by %14" PRIi64 " ticks (developer debug - ignore)\n",
			stc,
			stc > (int64_t)scr ? "ahead of" : "behind the",
			diff);
	}

	uint64_t scr_diff = 0;
	if (ctx->pids[pid].scr_updateCount > 0) {
		scr_diff = ltntstools_scr_diff(ctx->pids[pid].scr, scr);
	} else {
		ctx->pids[pid].scr_first = scr;
		ctx->pids[pid].scr_first_time = ctx->initial_time;
	}

	ctx->pids[pid].scr = scr;

	if (ctx->scr_linenr++ == 0) {
		printf("+SCR Timing           filepos ------------>                   SCR  <--- SCR-DIFF ------>  SCR             Walltime ----------------------------->  Drift\n");
		printf("+SCR Timing               Hex           Dec   PID       27MHz VAL       TICKS         uS  Timecode        Now                      secs               ms\n");
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

	time_t now = time(NULL);
	char time_str[64];
	sprintf(time_str, "%s", ctime(&now));
	time_str[ strlen(time_str) - 1] = 0;

	printf("SCR #%09" PRIu64 " -- %011" PRIx64 " %13" PRIu64 "  %04x  %14" PRIu64 "  %10" PRIu64 "  %9" PRIu64 "  %s  %s %08d.%03d %6s\n",
		ctx->pids[pid].scr_updateCount,
		filepos,
		filepos,
		pid,
		scr,
		scr_diff,
		scr_diff / 27,
		scr_ascii,
		time_str,
		(int)ts.tv_sec,
		(int)ts.tv_usec / 1000,
		walltimePCRReport);

	free(scr_ascii);
}
