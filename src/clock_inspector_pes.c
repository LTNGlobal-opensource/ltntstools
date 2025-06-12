#include "clock_inspector_public.h"

/* Ordered PTS handling */
static void ordered_clock_init(struct xorg_list *list)
{
	xorg_list_init(list);
}

/* The clock is a PTS 90KHz counter */
void ordered_clock_insert(struct xorg_list *list, struct ordered_clock_item_s *src)
{
	struct ordered_clock_item_s *e = calloc(1, sizeof(*e));
	if (!e) {
		return;
	}

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

void ordered_clock_dump(struct xorg_list *list, unsigned short pid)
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

static void printTrend(struct tool_context_s *ctx, uint16_t pid, struct kllineartrend_context_s *trend, pthread_mutex_t *mutex)
{
	/* Lock the struct, briefly prevent additional adds */
	pthread_mutex_lock(mutex);
	struct kllineartrend_context_s *trendDup = kllineartrend_clone(trend);
	if (!trendDup) {
		pthread_mutex_unlock(mutex);
		return;
	}
	pthread_mutex_unlock(mutex);

	if (ctx->enableTrendReport >= 2) {
		/* If the caller passes -L twice or more, save data set on every print.
		 */
		/* Don't need the mutex */
		kllineartrend_save_csv(trendDup, trendDup->name);
	}
	if (ctx->enableTrendReport >= 3) {
		/* If the caller passes -L three times or more, print the entire data set on every print.
		 * expensive console processing. Choose wisely my friend.
		 */
		/* Don't need the mutex */
		kllineartrend_printf(trendDup);
	}

	struct timeval t1, t2, t3;
	double slope, intersect, deviation, r2;

	gettimeofday(&t1, NULL);
	kllineartrend_calculate(trendDup, &slope, &intersect, &deviation);
	gettimeofday(&t2, NULL);
	kllineartrend_calculate_r_squared(trendDup, slope, intersect, &r2);
	gettimeofday(&t3, NULL);

#if 0
	/* slope calculate takes 1ms for 216000 entries (LTN573), r2 calculation is twice as long */
	int a_diffus = ltn_timeval_subtract_us(&t2, &t1);
	int b_diffus = ltn_timeval_subtract_us(&t3, &t2);

	printf("Trend calculation for %d/%d elements took %dus, r2 took %dus.\n",
		trendDup->count, trendDup->maxCount, a_diffus, b_diffus);
#endif

	char t[64];
	time_t now = time(NULL);
	sprintf(t, "%s", ctime(&now));
	t[ strlen(t) - 1] = 0;

	printf("PID 0x%04x - Trend '%s', %8d entries, Slope %18.8f, Deviation is %12.2f, r2 is %12.8f @ %s\n",
		pid,
		trendDup->name,
		trendDup->count,
		slope, deviation, r2, t);

	kllineartrend_free(trendDup);
}

void trendReportFree(struct tool_context_s *ctx)
{
	for (int i = 0; i <= 0x1fff; i++) {
		if (ctx->pids[i].trend_pts.clkToScrTicksDeltaTrend) {
			kllineartrend_free(ctx->pids[i].trend_pts.clkToScrTicksDeltaTrend);
		}
		if (ctx->pids[i].trend_dts.clkToScrTicksDeltaTrend) {
			kllineartrend_free(ctx->pids[i].trend_dts.clkToScrTicksDeltaTrend);
		}
	}
}

void trendReport(struct tool_context_s *ctx)
{
	for (int i = 0; i <= 0x1fff; i++) {
		if (ctx->pids[i].trend_pts.clkToScrTicksDeltaTrend) {
			printTrend(ctx, i, ctx->pids[i].trend_pts.clkToScrTicksDeltaTrend, &ctx->pids[i].trend_pts.trendLock);
		}
		if (ctx->pids[i].trend_dts.clkToScrTicksDeltaTrend) {
			printTrend(ctx, i, ctx->pids[i].trend_dts.clkToScrTicksDeltaTrend, &ctx->pids[i].trend_dts.trendLock);
		}
	}
}

void *trend_report_thread(void *tool_context)
{
    struct tool_context_s *ctx = tool_context;
	pthread_detach(ctx->trendThreadId);

	time_t next = time(NULL) + ctx->reportPeriod;
    while (ctx->enableTrendReport && gRunning) {
		usleep(250 * 1000);
		if (time(NULL) < next)
			continue;

        printf("Dumping trend report(s)\n");
        trendReport(ctx);
		next = time(NULL) + ctx->reportPeriod;
    }
	ctx->trendThreadComplete = 1;

    return NULL;
}

static ssize_t processPESHeader(uint8_t *buf, uint32_t lengthBytes, uint32_t pid, struct tool_context_s *ctx, uint64_t filepos, struct timeval ts,
	int64_t prior_pes_delivery_ticks,
	int64_t prior_pes_delivery_us)
{
	char time_str[64];

	time_t now = time(NULL);
	sprintf(time_str, "%s", ctime(&now));
	time_str[ strlen(time_str) - 1] = 0;

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

		/* Initialize the trend if needed */
		if (p->trend_pts.clkToScrTicksDeltaTrend == NULL) {
			char label[64];
			sprintf(&label[0], "PTS 0x%04x to Wallclock delta", pid);
			pthread_mutex_init(&p->trend_pts.trendLock, NULL);
			p->trend_pts.clkToScrTicksDeltaTrend = kllineartrend_alloc(ctx->trendSize, label);
		}
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

		if (p->trend_dts.clkToScrTicksDeltaTrend == NULL) {
			char label[64];
			sprintf(&label[0], "DTS 0x%04x to SCR tick delta", pid);
			pthread_mutex_init(&p->trend_dts.trendLock, NULL);
			p->trend_dts.clkToScrTicksDeltaTrend = kllineartrend_alloc(ctx->trendSize, label);
		}
	}

	struct klbs_context_s pbs, *bs = &pbs;
	klbs_init(bs);
	klbs_read_set_buffer(bs, buf, lengthBytes);

	ssize_t len = ltn_pes_packet_parse(&p->pes, bs, 1 /* SkipDataExtraction */);

	/* Track the difference in SCR clocks between this PTS header and the prior. */
	int64_t pts_scr_diff_ms = 0;
	int64_t dts_scr_diff_ms = 0;

	if ((p->pes.PTS_DTS_flags == 2) || (p->pes.PTS_DTS_flags == 3)) {
		p->pts_diff_ticks = ltntstools_pts_diff(p->pts_last.PTS, p->pes.PTS);
		if (p->pts_diff_ticks > (10 * 90000)) {
			p->pts_diff_ticks -= MAX_PTS_VALUE;
		}
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
		printf("+PTS/DTS Timing       filepos ------------>               PTS/DTS  <------- DIFF ------> <---- SCR <--PTS*300--------->  Walltime ----------------------------->  Drift\n");
		printf("+PTS/DTS Timing           Hex           Dec   PID       90KHz VAL       TICKS         MS   Diff MS  minus SCR        ms  Now                      secs               ms\n");
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
		int64_t pts_minus_scr_ticks = (p->pes.PTS * 300) - ctx->pids[ctx->scr_pid].scr;
		double d_pts_minus_scr_ticks = pts_minus_scr_ticks;
		d_pts_minus_scr_ticks /= 27000.0;

		/* Update the PTS/SCR linear trends. */
		p->trend_pts.last_clkToScrTicksDeltaTrend = now;
		p->trend_pts.counter++;
		p->trend_pts.inserted_counter++;
		if (p->trend_pts.counter > 16) {
			/* allow the first few samples to flow through the model and be ignored.
			 */
#if 0
			pthread_mutex_lock(&p->trend_pts.trendLock);
			kllineartrend_add(p->trend_pts.clkToScrTicksDeltaTrend, p->trend_pts.counter, d_pts_minus_scr_ticks);
			pthread_mutex_unlock(&p->trend_pts.trendLock);
#else
			struct timeval t1;
			gettimeofday(&t1, NULL);
			double x, y;

			x = t1.tv_sec + t1.tv_usec / 1000000.0;
			y = p->pes.PTS / 90000.0;
			if (p->trend_pts.first_x == 0)
				p->trend_pts.first_x = x;
			if (p->trend_pts.first_y == 0)
				p->trend_pts.first_y = y;

			pthread_mutex_lock(&p->trend_pts.trendLock);
			kllineartrend_add(p->trend_pts.clkToScrTicksDeltaTrend, x - p->trend_pts.first_x, y - p->trend_pts.first_y);
			pthread_mutex_unlock(&p->trend_pts.trendLock);
#endif
		}

		if (d_pts_minus_scr_ticks < 0 && ctx->enableNonTimingConformantMessages) {
			char str[64];
			sprintf(str, "%s", ctime(&ctx->current_stream_time));
			str[ strlen(str) - 1] = 0;
			printf("!PTS #%09" PRIi64 " Error. The PTS is arriving BEHIND the PCR, the PTS is late. The stream is not timing conformant @ %s\n",
				p->pts_count,
				str);
		}

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

		if (!ctx->order_asc_pts_output) {
			printf("PTS #%09" PRIi64
				" -- %011" PRIx64
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

			if (ctx->enablePESDeliveryReport) {
				printf("!PTS #%09" PRIi64 "                              %04x took %10" PRIi64 " SCR ticks to arrive, or %9.03f ms, %9" PRIi64 " uS walltime %s\n",
					p->pts_count - 1,
					pid,
					prior_pes_delivery_ticks,
					(double)prior_pes_delivery_ticks / 27000.0,
					prior_pes_delivery_us,
					prior_pes_delivery_ticks == 0 ? "(probably delivered in a single SCR interval period, so basically no ticks measured)" : "");
			}
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

		/* Disabled for now, TODO */
		int64_t dtsWalltimeDriftMs = 0;
		if (p->clk_dts_initialized) {
			dtsWalltimeDriftMs = ltntstools_clock_get_drift_ms(&p->clk_dts);
		}

		/* Calculate the offset between the DTS and the last good SCR, assumed to be on pid DEFAULT_SCR_PID. */
		int64_t dts_minus_scr_ticks = (p->pes.DTS * 300) - ctx->pids[ctx->scr_pid].scr;
		double d_dts_minus_scr_ticks = dts_minus_scr_ticks;
		d_dts_minus_scr_ticks /= 27000.0;

		/* Update the DTS/SCR linear trends. */
		p->trend_dts.last_clkToScrTicksDeltaTrend = now;
		p->trend_dts.counter++;
		if (p->trend_dts.counter > 16) {
			/* allow the first few samples to flow through the model and be ignored.
			 */
#if 0
			pthread_mutex_lock(&p->trend_dts.trendLock);
			kllineartrend_add(p->trend_dts.clkToScrTicksDeltaTrend, p->trend_dts.counter, d_dts_minus_scr_ticks);
			pthread_mutex_unlock(&p->trend_dts.trendLock);
#else
			struct timeval t1;
			gettimeofday(&t1, NULL);
			double x, y;

			x = t1.tv_sec + t1.tv_usec / 1000000.0;
			y = p->pes.DTS / 90000.0;
			if (p->trend_dts.first_x == 0)
				p->trend_dts.first_x = x;
			if (p->trend_dts.first_y == 0)
				p->trend_dts.first_y = y;

			pthread_mutex_lock(&p->trend_dts.trendLock);
			kllineartrend_add(p->trend_dts.clkToScrTicksDeltaTrend, x - p->trend_dts.first_x, y - p->trend_dts.first_y);
			pthread_mutex_unlock(&p->trend_dts.trendLock);
#endif
		}

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

		printf("DTS #%09" PRIi64
			" -- %011" PRIx64
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
			p->pes.DTS,
			p->dts_diff_ticks,
			(double)p->dts_diff_ticks / 90,
			dts_scr_diff_ms,
			dts_minus_scr_ticks,
			d_dts_minus_scr_ticks,
			time_str,
			(int)ts.tv_sec,
			(int)ts.tv_usec / 1000,
			dtsWalltimeDriftMs);
	}

	if (len > 0 && ctx->doPESStatistics > 1) {
		ltn_pes_packet_dump(&p->pes, "    ");
	}

	return len;
}

void processPESStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts)
{
	uint16_t pid = ltntstools_pid(pkt);
	struct pid_s *p = &ctx->pids[pid];
	int64_t prior_pes_delivery_ticks;
	int64_t prior_pes_delivery_us;

	int peshdr = ltntstools_payload_unit_start_indicator(pkt);

	int pesoffset = 0;
	if (peshdr) {
		pesoffset = ltntstools_contains_pes_header(pkt + 4, 188 - 4);

		/* Calculate how long the PREVIOUS PES took to arrive in SCR ticks. */
		prior_pes_delivery_ticks = p->scr_last_seen - p->scr_at_pes_unit_header;
		prior_pes_delivery_us = ltn_timeval_subtract_us(&p->scr_last_seen_ts, &p->scr_at_pes_unit_header_ts);

		p->scr_at_pes_unit_header = ctx->pids[ctx->scr_pid].scr;
		p->scr_at_pes_unit_header_ts = ts;
	} else {
		/* make a note of the last user SCR for this packet on this pid */
		p->scr_last_seen = ctx->pids[ctx->scr_pid].scr;
		p->scr_last_seen_ts = ts;
	}

	if (peshdr && pesoffset >= 0 && pid > 0) {
		processPESHeader(pkt + 4 + pesoffset, 188 - 4 - pesoffset, pid, ctx, filepos, ts, prior_pes_delivery_ticks, prior_pes_delivery_us);
	}
}
