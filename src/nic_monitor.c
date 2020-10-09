
#include "nic_monitor.h"

/* Reduce this to 4 * 32768 to simulate loss on a NIC with 600Mbps */
static int g_buffer_size_default = (2 * 1024 * 1024);
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

static void _processPackets(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr,
	const uint8_t *pkts, uint32_t pktCount, int isRTP)
{
	struct discovered_item_s *di = discovered_item_findcreate(ctx, ethhdr, iphdr, udphdr);
	di->isRTP = isRTP;

	struct timeval now, diff;
	gettimeofday(&now, NULL);
	if (di->iat_last_frame.tv_sec) {
		ltn_histogram_timeval_subtract(&diff, &now, &di->iat_last_frame);
		di->iat_cur_us = ltn_histogram_timeval_to_us(&diff);

		if (di->iat_cur_us <= di->iat_lwm_us)
			di->iat_lwm_us = di->iat_cur_us;
		if (di->iat_cur_us >= di->iat_hwm_us)
			di->iat_hwm_us = di->iat_cur_us;
	}
	di->iat_last_frame = now;

	ltntstools_pid_stats_update(&di->stats, pkts, pktCount);
}

static void pcap_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *pkt) 
{ 
	int isRTP = 0;

	if (h->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return;

	struct ether_header *eth = (struct ether_header *)pkt;
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip = (struct iphdr *)((u_char *)eth + sizeof(struct ether_header));

#ifdef __APPLE__
		if (ip->ip_p != IPPROTO_UDP)
			return;
#endif
#ifdef __linux__
		if (ip->protocol != IPPROTO_UDP)
			return;
#endif

		struct udphdr *udp = (struct udphdr *)((u_char *)ip + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udp + sizeof(struct udphdr));

		if (ctx->verbose) {
			struct in_addr dstaddr, srcaddr;
#ifdef __APPLE__
			srcaddr.s_addr = ip->ip_src.s_addr;
			dstaddr.s_addr = ip->ip_dst.s_addr;
#endif
#ifdef __linux__
			srcaddr.s_addr = ip->saddr;
			dstaddr.s_addr = ip->daddr;
#endif

			char src[24], dst[24];
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udp->uh_sport));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udp->uh_dport));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				
				src, dst,
				ntohs(udp->uh_ulen),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		if (ptr[0] != 0x47) {
			/* Make a rash assumption that's it's RTP where possible. */
			if (ptr[12] == 0x47) {
				ptr += 12;
				isRTP = 1;
			}
		}

		/* TS Packet, almost certainly */
		/* We can safely assume there are len / 188 packets. */
		int pktCount = ntohs(udp->uh_ulen) / 188;
		_processPackets(ctx, eth, ip, udp, ptr, pktCount, isRTP);
	}
}

static void *ui_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->ui_threadRunning = 1;
	ctx->ui_threadTerminate = 0;
	ctx->ui_threadTerminated = 0;
	ctx->trailerRow = DEFAULT_TRAILERROW;

	noecho();
	curs_set(0);
	start_color();
	init_pair(1, COLOR_WHITE, COLOR_BLUE);
	init_pair(2, COLOR_CYAN, COLOR_BLACK);
	init_pair(3, COLOR_RED, COLOR_BLACK);
	init_pair(4, COLOR_WHITE, COLOR_RED);

	while (!ctx->ui_threadTerminate) {

		time_t now;
		time(&now);

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
		int blen = 108 - (strlen(title_a) + strlen(title_c));
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
		mvprintw( 1, 0, "<--------------------------------------------------- M/BIT <------PACKETS <------CCErr <---IAT-(cur/min/max)");
		attroff(COLOR_PAIR(1));

		int streamCount = 1;
		struct discovered_item_s *di = NULL;
		pthread_mutex_lock(&ctx->lock);
		xorg_list_for_each_entry(di, &ctx->list, list) {

			if (di->stats.ccErrors)
				attron(COLOR_PAIR(3));

			mvprintw(streamCount + 2, 0, "%s %21s -> %21s  %6.2f  %13" PRIu64 " %12" PRIu64 "   %7d / %d / %d",
				di->isRTP ? "RTP" : "UDP",
				di->srcaddr,
				di->dstaddr,
				ltntstools_pid_stats_stream_get_mbps(&di->stats),
				di->stats.packetCount,
				di->stats.ccErrors,
				di->iat_cur_us, di->iat_lwm_us, di->iat_hwm_us);

			if (di->stats.ccErrors)
				attroff(COLOR_PAIR(3));

			streamCount++;
		}
		pthread_mutex_unlock(&ctx->lock);

		ctx->trailerRow = streamCount + 3;

		attron(COLOR_PAIR(2));
		mvprintw(ctx->trailerRow, 0, "q)uit r)eset");
		attroff(COLOR_PAIR(2));

		char tail_a[160], tail_b[160], tail_c[160];
		memset(tail_b, '-', sizeof(tail_b));
		sprintf(tail_a, "TSTOOLS_NIC_MONITOR");
		sprintf(tail_c, "%s", ctime(&now));
		blen = 109 - (strlen(tail_a) + strlen(tail_c));
		memset(tail_b, 0x20, sizeof(tail_b));
		tail_b[blen] = 0;

		attron(COLOR_PAIR(1));
		mvprintw(ctx->trailerRow + 1, 0, "%s%s%s", tail_a, tail_b, tail_c);
		attroff(COLOR_PAIR(1));

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

	int processed;

	time_t now;
	time(&now);
	if (ctx->file_next_write_time == 0) {
		ctx->file_next_write_time = now + ctx->file_write_interval;
	}

	while (!ctx->stats_threadTerminate) {
		/* Collect pcap packet loss stats */
		if (pcap_stats(ctx->descr, &ctx->pcap_stats) != 0) {
			/* Error */
		}

		processed = pcap_dispatch(ctx->descr, -1, pcap_callback, NULL);
		if (processed == 0)
			usleep(5 * 1000);

		time(&now);
		if ((ctx->file_prefix || ctx->detailed_file_prefix) && ctx->file_next_write_time <= now) {
			ctx->file_next_write_time = now + ctx->file_write_interval;
			/* TODO: We're writing small amounts of I/O in the network thread. */
			/*       Build a writer thread if we have hundreds of discovered streams. */
			discovered_items_file_summary(ctx);
		}

		if (ctx->endTime) {
			if (now >= ctx->endTime) {
				//kill(getpid(), 0);
				gRunning = 0;
				break;
			}
		}
	}
	ctx->stats_threadTerminated = 1;

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
	printf("  -d <dir> Write summary stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -w <dir> Write detailed pid stats per stream in this target directory prefix, every -n seconds.\n");
	printf("  -n <seconds> Interval to update -d file based stats [def: %d]\n", FILE_WRITE_INTERVAL);
	printf("  -F '<string>' Use a custom pcap filter. [def: '%s']\n", DEFAULT_PCAP_FILTER);
#if 0
	printf("  -o <output filename> (optional)\n");
#endif
	printf("  -S <number> Packet buffer size [def: %d] (min: 2048)\n", g_snaplen_default);
	printf("  -B <number> Buffer size [def: %d]\n", g_buffer_size_default);
}

int nic_monitor(int argc, char *argv[])
{
	int ch;
	int ret;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);
	ctx->file_write_interval = FILE_WRITE_INTERVAL;
	ctx->pcap_filter = DEFAULT_PCAP_FILTER;
	ctx->snaplen = g_snaplen_default;
	ctx->bufferSize = g_buffer_size_default;

	while ((ch = getopt(argc, argv, "?hd:B:D:F:i:t:vMn:w:S:")) != -1) {
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

	gRunning = 1;
	pthread_create(&ctx->stats_threadId, 0, stats_thread_func, ctx);

	if (ctx->monitor) {
		initscr();
		pthread_create(&ctx->ui_threadId, 0, ui_thread_func, ctx);
	}

	/* Start any threads, main loop processes keybaord. */
	signal(SIGINT, signal_handler);
	timeout(300);
	while (gRunning) {
		char c = getch();
		if (c == 'q')
			break;
		if (c == 'r') {
			discovered_items_stats_reset(ctx);
		}
		usleep(50 * 1000);
	}

	/* Shutdown stats collection */
	ctx->ui_threadTerminate = 1;
	ctx->stats_threadTerminate = 1;
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

	free(ctx->file_prefix);
	free(ctx->detailed_file_prefix);
	return 0;
}
