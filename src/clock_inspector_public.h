#ifndef CLOCK_INSPECTOR_PUBLIC_H
#define CLOCK_INSPECTOR_PUBLIC_H

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
#include "kl-lineartrend.h"

#define DEFAULT_SCR_PID 0x31
#define DEFAULT_TREND_SIZE (60 * 60 * 60) /* 1hr */
#define DEFAULT_TREND_REPORT_PERIOD 15

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

	/* Four vars that track when each TS packet arrives, and what SCR timestamp was during
	 * arrival. We use this to broadly measure the walltime an entire pess took to arrive,
	 * and the SCR ticket it took.
	 */
	uint64_t scr_at_pes_unit_header;
	uint64_t scr_last_seen; /* last scr when this pid was seen. Avoiding change 'scr' pid for now, risky? */
	struct timeval scr_at_pes_unit_header_ts;
	struct timeval scr_last_seen_ts;

	/* Guards: scr, scr_updateCount, clk_pts, clk_dts, clk_pts_initialized, clk_dts_initialized.
	 * Held briefly by the packet-processing thread at each write site. Deliberately
	 * separate from trend_pts/trend_dts.trendLock below, which guards unrelated,
	 * much-less-frequently-touched linear-trend state.
	 */
	pthread_mutex_t clockLock;

	/* PTS */
	uint64_t pts_count;
	struct ltn_pes_packet_s pts_last;
	int64_t pts_diff_ticks;
	uint64_t pts_last_scr; /* When we captured the last packet, this reflects the SCR at the time. */
	struct ltntstools_clock_s clk_pts;
	struct {
		pthread_mutex_t trendLock; /* Lock the trend when we add or when we clone the struct */
		struct kllineartrend_context_s *clkToScrTicksDeltaTrend;
		time_t last_clkToScrTicksDeltaTrend;
		time_t last_clkToScrTicksDeltaTrendReport; /* Recall whenever we've output a trend report */
		double counter;
		int inserted_counter;
		double first_x;
		double first_y;
	} trend_pts, trend_dts;

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
	int verbose;
	int enableNonTimingConformantMessages;
	int enableTrendReport;
	int enablePESDeliveryReport;
	int dumpHex;
	int trendSize;
	int reportPeriod;
	const char *iname;
	time_t initial_time;
	time_t current_stream_time;
	int64_t maxAllowablePTSDTSDrift;
//	uint32_t pid;
#define MAX_PIDS 8192
	struct pid_s pids[MAX_PIDS];
	pthread_t trendThreadId;
	int trendThreadComplete;

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

	/* Realtime websocket PCR feed + reference web UI (clock_inspector_ws.c).
	 * ws_port == 0 (the default, from the calloc'd ctx) disables the feature entirely,
	 * set via -W <port>. ws_priv is an opaque pointer to the libwebsockets-specific
	 * state (context, ring buffer, etc.) so no other clock_inspector_*.c translation
	 * unit needs to include <libwebsockets.h>. There is no separate broadcast
	 * thread: processSCRStats() calls ws_notify_pcr() directly, once per SCR tick
	 * observed on the designated PCR pid (ctx->scr_pid), so each websocket message
	 * corresponds exactly to one real PCR sample -- no polling, no aliasing.
	 */
	int ws_port;
	void *ws_priv;
	pthread_t ws_threadId;
	int ws_threadTerminate;
	int ws_threadTerminated;
};

extern int gRunning;

void processPacketStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts);
void pidReport(struct tool_context_s *ctx);

void kernel_check_socket_sizes(AVIOContext *i);
int validateClockMath();
int validateLinearTrend();
int validateClockLocking();
void processSCRStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts);

void processPESStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts);

void *trend_report_thread(void *tool_context);
void trendReport(struct tool_context_s *ctx);
void trendReportFree(struct tool_context_s *ctx);
void ordered_clock_dump(struct xorg_list *list, unsigned short pid);

/* Realtime websocket PCR feed, see clock_inspector_ws.c. All are no-ops (or return
 * an error) if ctx->ws_port <= 0.
 */
int   ws_initialize(struct tool_context_s *ctx);
void  ws_interrupt(struct tool_context_s *ctx);
void  ws_free(struct tool_context_s *ctx);
void *ws_thread_func(void *tool_context);

/* Called directly from processSCRStats()/processPESHeader() for each real PCR/
 * PTS/DTS tick observed -- one call in, at most one websocket message out.
 * driftMs is the same kind of quantity for all three (drift from walltime in
 * ms), computed exactly the same way as, and reusing the same values as, the
 * console reports (walltimePCRReport / ptsWalltimeDriftMs / dtsWalltimeDriftMs).
 * intervalMs is the time since this same pid's previous tick of this same
 * clock, in ms -- reusing scr_diff / pts_diff_ticks / dts_diff_ticks, already
 * computed for the console's "TICKS"/"DIFF" columns. Pass a negative value
 * (eg -1) when no prior tick exists yet (first sample for this pid/clock);
 * it's sent as JSON null rather than a bogus interval.
 *
 * ws_notify_pts()/ws_notify_dts() additionally take scrDriftMs: this PTS/DTS
 * minus the current SCR on ctx->scr_pid, in ms -- reusing the exact
 * d_pts_minus_scr_ticks/d_dts_minus_scr_ticks already computed for the
 * console's "PTS*300 minus SCR" column (and the "arriving BEHIND the PCR"
 * conformance check). Positive means the timestamp is still ahead of the PCR
 * (normal decode-buffer margin); zero or negative means the PCR has already
 * reached or passed it. Only meaningful once ctx->scr_pid has a valid SCR, so
 * haveScrDriftMs is 0 (and scrDriftMs is sent as JSON null) until then.
 */
void  ws_notify_pcr(struct tool_context_s *ctx, uint16_t pid, uint64_t ticks27MHz,
	int64_t driftMs, double intervalMs, struct timeval ts);
void  ws_notify_pts(struct tool_context_s *ctx, uint16_t pid, int64_t ticks90k,
	int64_t driftMs, double intervalMs, int haveScrDriftMs, double scrDriftMs, struct timeval ts);
void  ws_notify_dts(struct tool_context_s *ctx, uint16_t pid, int64_t ticks90k,
	int64_t driftMs, double intervalMs, int haveScrDriftMs, double scrDriftMs, struct timeval ts);

/* Broadcast once, the first time a given (pid, clockType) combination is
 * observed ("pcr"/"pts"/"dts"), so already-connected dashboards can add it to
 * their pid/clock picker live without polling. */
void  ws_notify_pid_seen(struct tool_context_s *ctx, uint16_t pid, const char *clockType);

#endif /* CLOCK_INSPECTOR_PUBLIC_H */