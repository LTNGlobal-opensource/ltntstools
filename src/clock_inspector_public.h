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
	struct pid_s pids[8192];
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
};

void processPacketStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts);
void pidReport(struct tool_context_s *ctx);

void kernel_check_socket_sizes(AVIOContext *i);
int validateClockMath();
int validateLinearTrend();
void processSCRStats(struct tool_context_s *ctx, uint8_t *pkt, uint64_t filepos, struct timeval ts);

#endif /* #define CLOCK_INSPECTOR_PUBLIC_H */