
#include "nic_monitor.h"

/* Reduce this to 4 * 32768 to simulate loss on a NIC with 600Mbps */
static int g_buffer_size_default = (32 * 1024 * 1024);
static int g_snaplen_default =
#ifdef __linux__
	BUFSIZ
#endif
#ifdef __APPLE__
	65535
#endif
;

static int gRunning = 0;

static struct tool_context_s g_ctx = { 0 };
static struct tool_context_s *ctx = &g_ctx;

#if defined(__linux__)
extern int pthread_setname_np(pthread_t thread, const char *name);
#endif

int ltnpthread_setname_np(pthread_t thread, const char *name)
{
#if defined(__linux__)
        return pthread_setname_np(thread, name);
#endif
#if defined(__APPLE__)
        /* We don't support thread naming on OSX, yet. */
        return 0;
#endif
}

static void *ui_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->ui_threadRunning = 1;
	ctx->ui_threadTerminate = 0;
	ctx->ui_threadTerminated = 0;
	ctx->trailerRow = DEFAULT_TRAILERROW;
	double totalMbps = 0;

	ltnpthread_setname_np(ctx->ui_threadId, "tstools-ui");
	pthread_detach(pthread_self());
	setlocale(LC_NUMERIC, "");

	noecho();
	curs_set(0);
	start_color();
	init_pair(1, COLOR_WHITE, COLOR_BLUE);
	init_pair(2, COLOR_CYAN, COLOR_BLACK);
	init_pair(3, COLOR_RED, COLOR_BLACK);
	init_pair(4, COLOR_WHITE, COLOR_RED);
	init_pair(5, COLOR_WHITE, COLOR_GREEN);
	init_pair(7, COLOR_YELLOW, COLOR_BLACK);

	while (!ctx->ui_threadTerminate) {

		totalMbps = 0;
		time_t now;
		time(&now);

		if (ctx->freezeDisplay & 1) {
			usleep(50 * 1000);
			continue;
		}

		clear();

		struct in_addr ip_net, ip_mask;
		ip_net.s_addr = ctx->netp;
		ip_mask.s_addr = ctx->maskp;
		//printf("network: %s\n", inet_ntoa(ip_net));
		//printf("   mask: %s\n", inet_ntoa(ip_mask));

		char title_a[160], title_b[160], title_c[160];
		sprintf(title_a, "%s", ctx->pcap_filter);
		char mask[64];
		sprintf(mask, "%s", inet_ntoa(ip_mask));
		sprintf(title_c, "NIC: %s (%s/%s) Dropped: %d/%d", ctx->ifname, inet_ntoa(ip_net), mask,
			ctx->pcap_stats.ps_drop,
			ctx->pcap_stats.ps_ifdrop);
		int blen = 111 - (strlen(title_a) + strlen(title_c));
		memset(title_b, 0x20, sizeof(title_b));
		title_b[blen] = 0;

		if (ctx->pcap_stats.ps_drop || ctx->pcap_stats.ps_ifdrop) {
			attron(COLOR_PAIR(4));
		} else {
			attron(COLOR_PAIR(1));
		}
		mvprintw( 0, 0, "%s%s%s", title_a, title_b, title_c);

		if (ctx->pcap_stats.ps_drop || ctx->pcap_stats.ps_ifdrop) {
			attroff(COLOR_PAIR(4));
		} else {
			attroff(COLOR_PAIR(1));
		}

		attron(COLOR_PAIR(1));
		mvprintw( 1, 0, "<--------------------------------------------------- M/BIT <---------PACKETS <------CCErr <-IAT(uS)------------");
		attroff(COLOR_PAIR(1));

		int streamCount = 1;
		struct discovered_item_s *di = NULL;
		pthread_mutex_lock(&ctx->lock);
		xorg_list_for_each_entry(di, &ctx->list, list) {

			if (di->stats.ccErrors)
				discovered_item_state_set(di, DI_STATE_CC_ERROR);
			else
				discovered_item_state_clr(di, DI_STATE_CC_ERROR);

			if (discovered_item_state_get(di, DI_STATE_CC_ERROR))
				attron(COLOR_PAIR(3));

			if (discovered_item_state_get(di, DI_STATE_SELECTED))
				attron(COLOR_PAIR(5));

			if (discovered_item_state_get(di, DI_STATE_DST_DUPLICATE))
				attron(COLOR_PAIR(4));

			totalMbps += ltntstools_pid_stats_stream_get_mbps(&di->stats);
			mvprintw(streamCount + 2, 0, "%s %21s -> %21s  %6.2f  %'16" PRIu64 " %12" PRIu64 "   %7d / %d / %d",
				di->isRTP ? "RTP" : "UDP",
				di->srcaddr,
				di->dstaddr,
				ltntstools_pid_stats_stream_get_mbps(&di->stats),
				di->stats.packetCount,
				di->stats.ccErrors,
				di->iat_cur_us, di->iat_lwm_us, di->iat_hwm_us);

			if (discovered_item_state_get(di, DI_STATE_DST_DUPLICATE))
				attroff(COLOR_PAIR(4));

			if (discovered_item_state_get(di, DI_STATE_SELECTED))
				attroff(COLOR_PAIR(5));

			if (discovered_item_state_get(di, DI_STATE_CC_ERROR))
				attroff(COLOR_PAIR(3));

			if (discovered_item_state_get(di, DI_STATE_PCAP_RECORDING)) {

				char fn[512] = { 0 };
				int ret = ltntstools_segmentwriter_get_current_filename(di->pcapRecorder, &fn[0], sizeof(fn));
				if (ret < 0)
					sprintf(fn, "pending open file");

				double fsusedpct = 100.0 - ltntstools_segmentwriter_get_freespace_pct(di->pcapRecorder);
				int segcount = ltntstools_segmentwriter_get_segment_count(di->pcapRecorder);
				double totalsize = ltntstools_segmentwriter_get_recording_size(di->pcapRecorder);
				totalsize /= 1048576; /* MB */
				int mb = 1;
				if (totalsize > 4000) {
					totalsize /= 1024; /* Convert to GB */
					mb = 0;
				}

				time_t startTime = ltntstools_segmentwriter_get_recording_start_time(di->pcapRecorder);
				char st[64];
				sprintf(st, "%s", ctime(&startTime));
				st[ strlen(st) - 1] = 0;

				streamCount++;
				mvprintw(streamCount + 2, 0, " -> Segmented recording to ... %s", fn);

				double fs_full_warning_level = 80.0;
				if (fsusedpct > fs_full_warning_level)
					attron(COLOR_PAIR(3));

				streamCount++;
				mvprintw(streamCount + 2, 0, "    %d segment%s @ %'.02f%s, %s fs %5.02f%% full, since %s",
					segcount,
					segcount == 1 ? "" : "(s)",
					totalsize,
					mb == 1 ? "MB" : "GB",
					dirname(&fn[0]),
					fsusedpct,
					st);

				if (fsusedpct > fs_full_warning_level)
					attroff(COLOR_PAIR(3));

				int qdepth = ltntstools_segmentwriter_get_queue_depth(di->pcapRecorder);
				if (qdepth > 300 * 1000) {
					attron(COLOR_PAIR(7));
					streamCount++;
					mvprintw(streamCount + 2, 0, "    Recorder I/O is falling behind realtime, %d items waiting", qdepth);
					attroff(COLOR_PAIR(7));
				}
			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_PIDS)) {
				for (int i = 0; i < MAX_PID; i++) {
					if (di->stats.pids[i].enabled) {
						streamCount++;
						if (i == 0) {
							mvprintw(streamCount + 2, 0, " -> PID Report");
							mvprintw(streamCount + 3, 0,
								" -> None 1316 pkts  %" PRIi64, di->notMultipleOfSevenError);
						}

						mvprintw(streamCount + 2, 37, "0x%04x (%4d)  %6.2f %'17" PRIu64 " %12" PRIu64 "\n",
							i,
							i,
							ltntstools_pid_stats_pid_get_mbps(&di->stats, i),
							di->stats.pids[i].packetCount,
							di->stats.pids[i].ccErrors);
					}
				}
				streamCount++;
			}

			if (discovered_item_state_get(di, DI_STATE_SHOW_TR101290)) {
#if 0
        /* Priority 1 */
        E101290_P1_1__TS_SYNC_LOSS,
        E101290_P1_2__SYNC_BYTE_ERROR,
        E101290_P1_3__PAT_ERROR,
        E101290_P1_3a__PAT_ERROR_2,
        E101290_P1_4__CONTINUITY_COUNTER_ERROR,
        E101290_P1_5__PMT_ERROR,
        E101290_P1_5a__PMT_ERROR_2,
        E101290_P1_6__PID_ERROR,

        /* Priority 2 */
        E101290_P2_1__TRANSPORT_ERROR,
        E101290_P2_2__CRC_ERROR,
        E101290_P2_3__PCR_ERROR,
        E101290_P2_3a__PCR_REPETITION_ERROR,
        E101290_P2_4__PCR_ACCURACY_ERROR,
        E101290_P2_5__PTS_ERROR,
        E101290_P2_6__CAT_ERROR,

#endif
				streamCount++;
				mvprintw(streamCount + 2, 0, " -> TR101290 Status (NOT YET SUPPORTED)");
				streamCount++;
				int p1col = 10;

				/* Everything RED until further notice */
				attron(COLOR_PAIR(3));
				mvprintw(streamCount + 2, p1col, "P1.1  BAD [TS SYNC  ]");
				attroff(COLOR_PAIR(3));

				attron(COLOR_PAIR(6));
				mvprintw(streamCount + 3, p1col, "P1.2  OK  [SYNC BYTE]");
				mvprintw(streamCount + 4, p1col, "P1.3  OK  [PAT      ]");
				mvprintw(streamCount + 5, p1col, "P1.3a OK  [PAT 2    ]");
				mvprintw(streamCount + 6, p1col, "P1.4  OK  [CC       ]");
				mvprintw(streamCount + 7, p1col, "P1.5  OK  [PMT      ]");
				mvprintw(streamCount + 8, p1col, "P1.5a OK  [PMT 2    ]");
				mvprintw(streamCount + 9, p1col, "P1.6  OK  [PID      ]");

				int p2col = 45;
				mvprintw(streamCount + 2, p2col, "P2.1  OK  [TRANSPORT     ]");
				mvprintw(streamCount + 3, p2col, "P2.2  OK  [CRC           ]");
				mvprintw(streamCount + 4, p2col, "P2.3  OK  [PCR           ]");
				mvprintw(streamCount + 5, p2col, "P2.3a OK  [PCR REPETITION]");
				mvprintw(streamCount + 6, p2col, "P2.4  OK  [PCR ACCURACY  ]");
				mvprintw(streamCount + 7, p2col, "P2.5  OK  [PTS           ]");
				attroff(COLOR_PAIR(6));

				attron(COLOR_PAIR(3));
				mvprintw(streamCount + 8, p2col, "P2.6  BAD [CAT           ]");
				attroff(COLOR_PAIR(3));

				streamCount += 8;


			}

			streamCount++;
		}
		pthread_mutex_unlock(&ctx->lock);

		ctx->trailerRow = streamCount + 3;

		attron(COLOR_PAIR(2));
#if 1
		mvprintw(ctx->trailerRow, 0, "q)uit r)eset D)eselect S)elect R)ecord P)ids f)reeze");
#else
		mvprintw(ctx->trailerRow, 0, "q)uit r)eset D)eselect S)elect R)ecord P)ids f)reeze T)R101290  using: %d free: %d",
			ctx->rebalance_last_buffers_used,
			ctx->listpcapFreeDepth);
#endif
		attroff(COLOR_PAIR(2));

		char tail_a[160], tail_b[160], tail_c[160];
		attron(COLOR_PAIR(1));

		char s[64];
		sprintf(s, "%s", ctime(&now));
		s[ strlen(s) - 1 ] = 0;
		memset(tail_b, '-', sizeof(tail_b));
		sprintf(tail_a, "%s                           %7.02f", s, totalMbps);
		sprintf(tail_c, "Since: %s", ctime(&ctx->lastResetTime));
		blen = 112 - (strlen(tail_a) + strlen(tail_c));
		memset(tail_b, 0x20, sizeof(tail_b));
		tail_b[blen] = 0;

		mvprintw(ctx->trailerRow + 1, 0, "%s%s%s", tail_a, tail_b, tail_c);

		attroff(COLOR_PAIR(1));

		/* -- */
		refresh();

		usleep(200 * 1000);
	}
	ctx->ui_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

static void *stats_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->stats_threadRunning = 1;
	ctx->stats_threadTerminate = 0;
	ctx->stats_threadTerminated = 0;

	ltnpthread_setname_np(ctx->stats_threadId, "tstools-stats");
	pthread_detach(pthread_self());

	time_t now;
	time(&now);
	if (ctx->file_next_write_time == 0) {
		ctx->file_next_write_time = now + ctx->file_write_interval;
	}

	int workdone = 0;
	while (!ctx->stats_threadTerminate) {

		workdone = 0;
		int count = pcap_queue_service(ctx);
		if (count)
			workdone++;

		time(&now);
		if ((ctx->file_prefix || ctx->detailed_file_prefix) && ctx->file_next_write_time <= now) {
			ctx->file_next_write_time = now + ctx->file_write_interval;
			discovered_items_file_summary(ctx);
			workdone++;
		}

		/* We don't want the thread thrashing when we have nothing to process. */
		if (!workdone)
			usleep(1 * 1000);
	}
	ctx->stats_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

static void pcap_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *pkt) 
{
	pcap_update_statistics(ctx, h, pkt); /* Update the stream stats realtime to avoid queue jitter */
	pcap_queue_push(ctx, h, pkt); /* Push the packet onto a deferred queue for late IO processing. */
}

static void *pcap_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->pcap_threadRunning = 1;
	ctx->pcap_threadTerminate = 0;
	ctx->pcap_threadTerminated = 0;

	int processed;

	ltnpthread_setname_np(ctx->pcap_threadId, "tstools-pcap");
	pthread_detach(pthread_self());

	time_t lastStatsCheck = 0;

	ctx->descr = pcap_create(ctx->ifname, ctx->errbuf);
	if (ctx->descr == NULL) {
		fprintf(stderr, "Error, %s\n", ctx->errbuf);
		exit(1);
	}

	pcap_set_snaplen(ctx->descr, ctx->snaplen);
	pcap_set_promisc(ctx->descr,
#ifdef __linux__
		-1
#endif
#ifdef __APPLE__
		1
#endif
	);

	if (ctx->bufferSize != -1) {
		int ret = pcap_set_buffer_size(ctx->descr, ctx->bufferSize);
		if (ret == PCAP_ERROR_ACTIVATED) {
			fprintf(stderr, "Unable to set -B buffersize to %d, already activated\n", ctx->bufferSize);
			exit(0);
		}
		if (ret != 0) {
			fprintf(stderr, "Unable to set -B buffersize to %d\n", ctx->bufferSize);
			exit(0);
		}
	}

	int ret = pcap_activate(ctx->descr);
	if (ret != 0) {
		if (ret == PCAP_ERROR_PERM_DENIED) {
			fprintf(stderr, "Error, permission denied.\n");
		}
		if (ret == PCAP_ERROR_NO_SUCH_DEVICE) {
			fprintf(stderr, "Error, network interface '%s' not found.\n", ctx->ifname);
		}
		fprintf(stderr, "Error, pcap_activate, %s\n", pcap_geterr(ctx->descr));
		printf("\nAvailable interfaces:\n");
		networkInterfaceList();
		exit(1);
	}

	/* TODO: We should craft the filter to be udp dst 224.0.0.0/4 and then
	 * we don't need to manually filter in our callback.
	 */
	struct bpf_program fp;
	ret = pcap_compile(ctx->descr, &fp, ctx->pcap_filter, 0, ctx->netp);
	if (ret == -1) {
		fprintf(stderr, "Error, pcap_compile, %s\n", pcap_geterr(ctx->descr));
		exit(1);
	}

	ret = pcap_setfilter(ctx->descr, &fp);
	if (ret == -1) {
		fprintf(stderr, "Error, pcap_setfilter\n");
		exit(1);
	}

	pcap_setnonblock(ctx->descr, 1, ctx->errbuf);

	while (!ctx->pcap_threadTerminate) {

		processed = pcap_dispatch(ctx->descr, -1, pcap_callback, NULL);
		if (processed == 0) {
			ctx->pcap_dispatch_miss++;
			usleep(1 * 1000);
		}

		time_t now;
		time(&now);

		/* Querying stats repeatidly is cpu expensive, we only need it 1sec intervals. */
		if (lastStatsCheck == 0) {
			/* Collect pcap packet loss stats */
			if (pcap_stats(ctx->descr, &ctx->pcap_stats_startup) != 0) {
				/* Error */
			}
		}

		if (now != lastStatsCheck) {
			lastStatsCheck = now;
			/* Collect pcap packet loss stats */
			struct pcap_stat tmp;
			if (pcap_stats(ctx->descr, &tmp) != 0) {
				/* Error */
			}

			ctx->pcap_stats.ps_recv = tmp.ps_recv - ctx->pcap_stats_startup.ps_recv;
			ctx->pcap_stats.ps_drop = tmp.ps_drop - ctx->pcap_stats_startup.ps_drop;
			ctx->pcap_stats.ps_ifdrop = tmp.ps_ifdrop - ctx->pcap_stats_startup.ps_ifdrop;
		}

		pcap_queue_rebalance(ctx);

		if (ctx->endTime) {
			if (now >= ctx->endTime) {
				//kill(getpid(), 0);
				gRunning = 0;
				break;
			}
		}
	}
	ctx->pcap_threadTerminated = 1;

	pthread_exit(NULL);
	return 0;
}

static void signal_handler(int signum)
{
	if (!ctx->monitor && signum == SIGINT)
		printf("\nUser requested terminate.\n");

	gRunning = 0;
}

static void usage(const char *progname)
{
	printf("A tool to monitor PCAP multicast ISO13818 traffic.\n");
	printf("Usage:\n");
	printf("  -i <iface>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
	printf("  -M Display an interactive console with stats.\n");
	printf("  -D <dir> Write any PCAP recordings in this target directory prefix. [def: /tmp]\n");
	printf("  -d <dir> Write summary stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -w <dir> Write detailed pid stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -n <seconds> Interval to update -d file based stats [def: %d]\n", FILE_WRITE_INTERVAL);
	printf("  -F '<string>' Use a custom pcap filter. [def: '%s']\n", DEFAULT_PCAP_FILTER);
#if 0
	printf("  -o <output filename> (optional)\n");
#endif
	printf("  -S <number> Packet buffer size [def: %d] (min: 2048)\n", g_snaplen_default);
	printf("  -B <number> Buffer size [def: %d]\n", g_buffer_size_default);
	printf("  -R Automatically Record all discovered streams\n");
}

int nic_monitor(int argc, char *argv[])
{
	int ch;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);

	pthread_mutex_init(&ctx->lockpcap, NULL);
	xorg_list_init(&ctx->listpcapFree);
	xorg_list_init(&ctx->listpcapUsed);

	pcap_queue_initialize(ctx);

	ctx->file_write_interval = FILE_WRITE_INTERVAL;
	ctx->pcap_filter = DEFAULT_PCAP_FILTER;
	ctx->snaplen = g_snaplen_default;
	ctx->bufferSize = g_buffer_size_default;

	while ((ch = getopt(argc, argv, "?hd:B:D:F:i:t:vMn:w:RS:")) != -1) {
		switch (ch) {
		case 'B':
			ctx->bufferSize = atoi(optarg);
			if (ctx->bufferSize < (2 * 1048576))
				ctx->bufferSize = 2 * 1048576;
			break;
		case 'd':
			free(ctx->file_prefix);
			ctx->file_prefix = strdup(optarg);
			break;
		case 'F':
			ctx->pcap_filter = strdup(optarg);
			break;
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->ifname = optarg;
			if (networkInterfaceExists(ctx->ifname) == 0) {
				fprintf(stderr, "\nNo such network interface '%s', available interfaces:\n", ctx->ifname);
				networkInterfaceList();
				printf("\n");
				exit(1);
			}
			break;
		case 'n':
			ctx->file_write_interval = atoi(optarg);
			if (ctx->file_write_interval < 1)
				ctx->file_write_interval = 1;
			break;
		case 't':
			time(&ctx->endTime);
			ctx->endTime += atoi(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'M':
			ctx->monitor = 1;
			break;
		case 'D':
			ctx->recordingDir = optarg;
			break;
		case 'E':
		{
			struct parser_ippid_s p;
			if (parsers_ippid_parse(optarg, &p) < 0) {
				fprintf(stderr, "Unable to parse -D input\n");
				exit(0);
			}

			printf("-D %s\n", p.ui_address_ip_pid);
		}
			break;
		case 'S':
			ctx->snaplen = atoi(optarg);
			if (ctx->snaplen < 2048)
				ctx->snaplen = 2048;
			break;
		case 'w':
			free(ctx->detailed_file_prefix);
			ctx->detailed_file_prefix = strdup(optarg);
			break;
		case 'R':
			ctx->automaticallyRecordStreams = 1;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->ifname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\nError, -i is mandatory.\n\n");
		exit(1);
	}

	printf("  iface: %s\n", ctx->ifname);

	pcap_lookupnet(ctx->ifname, &ctx->netp, &ctx->maskp, ctx->errbuf);

	struct in_addr ip_net, ip_mask;
	ip_net.s_addr = ctx->netp;
	ip_mask.s_addr = ctx->maskp;
	printf("network: %s\n", inet_ntoa(ip_net));
	printf("   mask: %s\n", inet_ntoa(ip_mask));
	printf(" filter: %s\n", ctx->pcap_filter);
	printf("snaplen: %d\n", ctx->snaplen);
	printf("buffSiz: %d\n", ctx->bufferSize);
#if 0
	ctx->descr = pcap_create(ctx->ifname, ctx->errbuf);
	if (ctx->descr == NULL) {
		fprintf(stderr, "Error, %s\n", ctx->errbuf);
		exit(1);
	}

	pcap_set_snaplen(ctx->descr, ctx->snaplen);
	pcap_set_promisc(ctx->descr,
#ifdef __linux__
		-1
#endif
#ifdef __APPLE__
		1
#endif
	);

	if (ctx->bufferSize != -1) {
		int ret = pcap_set_buffer_size(ctx->descr, ctx->bufferSize);
		if (ret == PCAP_ERROR_ACTIVATED) {
			fprintf(stderr, "Unable to set -B buffersize to %d, already activated\n", ctx->bufferSize);
			exit(0);
		}
		if (ret != 0) {
			fprintf(stderr, "Unable to set -B buffersize to %d\n", ctx->bufferSize);
			exit(0);
		}
	}

	ret = pcap_activate(ctx->descr);
	if (ret != 0) {
		if (ret == PCAP_ERROR_PERM_DENIED) {
			fprintf(stderr, "Error, permission denied.\n");
		}
		if (ret == PCAP_ERROR_NO_SUCH_DEVICE) {
			fprintf(stderr, "Error, network interface '%s' not found.\n", ctx->ifname);
		}
		fprintf(stderr, "Error, pcap_activate, %s\n", pcap_geterr(ctx->descr));
		exit(1);
	}

	/* TODO: We should craft the filter to be udp dst 224.0.0.0/4 and then
	 * we don't need to manually filter in our callback.
	 */
	struct bpf_program fp;
	ret = pcap_compile(ctx->descr, &fp, ctx->pcap_filter, 0, ctx->netp);
	if (ret == -1) {
		fprintf(stderr, "Error, pcap_compile, %s\n", pcap_geterr(ctx->descr));
		exit(1);
	}

	ret = pcap_setfilter(ctx->descr, &fp);
	if (ret == -1) {
		fprintf(stderr, "Error, pcap_setfilter\n");
		exit(1);
	}

	pcap_setnonblock(ctx->descr, 1, ctx->errbuf);

#endif
	gRunning = 1;
	pthread_create(&ctx->stats_threadId, 0, stats_thread_func, ctx);
	pthread_create(&ctx->pcap_threadId, 0, pcap_thread_func, ctx);

	if (ctx->monitor) {
		initscr();
		pthread_create(&ctx->ui_threadId, 0, ui_thread_func, ctx);
	}

	/* Start any threads, main loop processes keybaord. */
	signal(SIGINT, signal_handler);
	timeout(300);

	time(&ctx->lastResetTime);
	while (gRunning) {
		char c = getch();
		if (c == 'q')
			break;
		if (c == 'f') {
			ctx->freezeDisplay++;
		}
		if (c == 'r') {
			time(&ctx->lastResetTime);
			discovered_items_stats_reset(ctx);
		}
		if (c == 'D') {
			discovered_items_select_none(ctx);
		}
		if (c == 'S') {
			discovered_items_select_all(ctx);
		}
		if (c == 'T') {
			discovered_items_select_show_tr101290_toggle(ctx);
		}
		if (c == 'R') {
			discovered_items_select_record_toggle(ctx);
		}
		if (c == 'P') {
			discovered_items_select_show_pids_toggle(ctx);
		}

		/* Cursor key support */
		if (c == 0x1b) {
			c = getch();
			if (c == 0x5b) {
				c = getch();
				if (c == 0x41) { /* Up */
					discovered_items_select_prev(ctx);
				} else
				if (c == 0x42) { /* Down */
					discovered_items_select_next(ctx);
				} else
				if (c == 0x43) { /* Right */
					discovered_items_select_first(ctx);
				} else
				if (c == 0x44) { /* Left */
				}
			}
		}

		usleep(50 * 1000);
	}

	discovered_items_record_abort(ctx);

	/* Shutdown stats collection */
	ctx->ui_threadTerminate = 1;
	ctx->pcap_threadTerminate = 1;
	ctx->stats_threadTerminate = 1;
	while (!ctx->pcap_threadTerminated)
		usleep(50 * 1000);
	while (!ctx->stats_threadTerminated)
		usleep(50 * 1000);

	/* Shutdown ui */
	if (ctx->monitor) {
		while (!ctx->ui_threadTerminated) {
			usleep(50 * 1000);
			printf("Blocked on ui\n");
		}
		endwin();
	}

	discovered_items_console_summary(ctx);

printf("pcap_free_miss %" PRIi64 "\n", ctx->pcap_free_miss);
printf("pcap_dispatch_miss %" PRIi64 "\n", ctx->pcap_dispatch_miss);
printf("ctx->listpcapFreeDepth %d\n", ctx->listpcapFreeDepth);
printf("ctx->listpcapUsedDepth %d\n", ctx->listpcapUsedDepth);
printf("ctx->rebalance_last_buffers_used %d\n", ctx->rebalance_last_buffers_used);

	printf("pcap nic '%s' stats: dropped: %d/%d\n",
		ctx->ifname, ctx->pcap_stats.ps_drop, ctx->pcap_stats.ps_ifdrop);

	pcap_queue_free(ctx);

	printf("Flushing the streams and recorders...\n");
	discovered_items_free(ctx);

	free(ctx->file_prefix);
	free(ctx->detailed_file_prefix);
	return 0;
}
