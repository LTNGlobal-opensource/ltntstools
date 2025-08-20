#include "clock_inspector_public.h"

int gRunning = 1;
static void signal_handler(int signum)
{
	gRunning = 0;
}

static void *notification_callback(struct tool_context_s *ctx, enum ltntstools_notification_event_e event,
	const struct ltntstools_stream_statistics_s *stats,
	const struct ltntstools_pid_statistics_s *pid)
{
	struct timeval ts;
	gettimeofday(&ts, NULL);

#if 0
	printf("%d.%06d: %s stream %p pid %p\n", (int)ts.tv_sec, (int)ts.tv_usec,
		ltntstools_notification_event_name(event),
		stats, pid);
#endif

	if (event == EVENT_UPDATE_PCR_MBPS) {
		double bps;
		ltntstools_bitrate_calculator_query_bitrate(ctx->libstats, &bps);
		printf("+TS PCR computed bitrate is %3.2f [ %f ]\n", bps / 1000000.0, bps);
	}
	return NULL;	
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
	printf("  -Z Suppress any warnings relating to non-conformant stream timing issues [def: warnings are output]\n");
	printf("  -L Enable printing of PTS to SCR linear trend report [def: no]\n");
	printf("  -Y Enable printing of 'PES took x ms' walltime and tick delivery times within a stream [def: no]\n");
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
	printf("  -A <number> default trend size [def: %d]\n", DEFAULT_TREND_SIZE);
	printf("      108000 is 1hr of 30fps, 216000 is 1hr of 60fps, 5184000 is 24hrs of 60fps\n");
	printf("  -B <seconds> trend report output period [def: %d]\n", DEFAULT_TREND_REPORT_PERIOD);

	printf("\n  Example UDP or RTP:\n");
	printf("    tstools_clock_inspector -i 'udp://227.1.20.80:4002?localaddr=192.168.20.45&buffer_size=2500000&overrun_nonfatal=1&fifo_size=50000000' -S 0x31 -p\n");
}

int clock_inspector(int argc, char *argv[])
{
	int ch;

	struct tool_context_s *ctx = calloc(1, sizeof(*ctx));
	ctx->doPacketStatistics = 1;
	ctx->doSCRStatistics = 0;
	ctx->doPESStatistics = 0;
	ctx->maxAllowablePTSDTSDrift = 700;
	ctx->scr_pid = DEFAULT_SCR_PID;
	ctx->enableNonTimingConformantMessages = 1;
	ctx->enableTrendReport = 0;
	ctx->trendSize = DEFAULT_TREND_SIZE;
	ctx->reportPeriod = DEFAULT_TREND_REPORT_PERIOD;
	int progressReport = 0;
	int stopSeconds = 0;

	/* We use this specifically for tracking PCR walltime drift */
	ltntstools_pid_stats_alloc(&ctx->libstats);

    while ((ch = getopt(argc, argv, "?dhi:spt:vA:B:T:D:LPRS:X:YZ")) != -1) {
		switch (ch) {
		case 'A':
			ctx->trendSize = atoi(optarg);
			if (ctx->trendSize < 60) {
				ctx->trendSize = 60;
			}
			break;
		case 'B':
			ctx->reportPeriod = atoi(optarg);
			if (ctx->reportPeriod < 5) {
				ctx->reportPeriod = 5;
			}
			break;
		case 'd':
			ctx->dumpHex++;
			break;
		case 'i':
			ctx->iname = optarg;
			break;
		case 'p':
			ctx->doSCRStatistics = 1; /* We need SCR stats also, because some of the PES stats make reference to the SCR */
			ctx->doPESStatistics++;
			break;
		case 'L':
			ctx->enableTrendReport++;
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
			ltntstools_notification_register_callback(ctx->libstats, EVENT_UPDATE_PCR_MBPS, ctx,
				(ltntstools_notification_callback)notification_callback);

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
		case 'Y':
			ctx->enablePESDeliveryReport = 1;
			break;
		case 't':
			stopSeconds = atoi(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'X':
			/* Keep valgrind happy */
			ltntstools_pid_stats_free(ctx->libstats);
			ctx->libstats = NULL;

			if (atoi(optarg) == 1) {
				return validateClockMath();
			} else
			if (atoi(optarg) == 2) {
				return validateLinearTrend();
			}
		case 'Z':
			ctx->enableNonTimingConformantMessages = 0;
			break;
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

	int blen = 188 * 7;
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

	pthread_create(&ctx->trendThreadId, NULL, trend_report_thread, ctx);

	/* TODO: Replace this with avio so we can support streams. */
	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i error, unable to open file or url\n");
		return 1;
	}

	kernel_check_socket_sizes(puc);
	if (ctx->enableTrendReport) {
		printf("Enabled Linear Trend reporting for PTS to SCR deltas\n");
	}

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
		if (rlen < 0) {
			//fprintf(stderr, "avio_read() < 0 read, ret = %d, shutting down\n", rlen);
			break;
		}

#if 0
		FILE *fh = fopen("/tmp/ci-delay.txt", "rb");
		if (fh) {
			char str[64] = { 0 };
			fread(str, 1, sizeof(str), fh);
			fclose(fh);

			int delayms = atoi(str);
			usleep(delayms * 1000);
		}
#endif

		streamPosition += rlen;

		for (int i = 0; i < rlen; i += 188) {

			filepos = (streamPosition - rlen) + i;

			uint8_t *p = (buf + i);

			struct timeval ts;
			gettimeofday(&ts, NULL);

			/* Push one packet into the stats layer - so we can compute walltime and jitter with finer granuality */
			ltntstools_pid_stats_update(ctx->libstats, p, 1);

			if (ctx->doPacketStatistics) {
				processPacketStats(ctx, p, filepos, ts);
			}

			if (ctx->doSCRStatistics) {
				processSCRStats(ctx, p, filepos, ts);
			}

			if (ctx->doPESStatistics) {
				/* Big caveat here: We expect the PES header to be contained
				 * somewhere (anywhere) in this single packet, and we only parse
				 * enough bytes to extract PTS and DTS.
				 */
				processPESStats(ctx, p, filepos, ts);
			}

			ctx->ts_total_packets++;

		}
		if (progressReport) {
			fprintf(stderr, "\rprocessing ... %.02f%%",
				(double)(((double)filepos / (double)fileLengthBytes) * 100.0));
		}
	}
	avio_close(puc);
	while (ctx->trendThreadComplete != 1) {
		usleep(50 * 1000);
	}

	if (progressReport) {
		fprintf(stderr, "\ndone\n");
	}

	printf("\n");
	pidReport(ctx);
	if (ctx->enableTrendReport) {
		trendReport(ctx);
		trendReportFree(ctx);
	}

	if (ctx->libstats) {
		ltntstools_notification_unregister_callbacks(ctx->libstats);
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

	free(ctx);
	return 0;
}
