/* Copyright LiveTimeNet, Inc. 2018. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <curses.h>
#include <inttypes.h>
#include <pthread.h>
#include "pids.h"
#include "xorg-list.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define DEFAULT_TRAILERROW 18
#define FILE_WRITE_INTERVAL 5
#define DEFAULT_PCAP_FILTER "udp dst portrange 4000-4999"

static int gRunning = 0;

struct tool_context_s
{
	char *ifname;
	int verbose;
	int monitor;
	time_t endTime;

	pthread_t stats_threadId;
	int stats_threadTerminate, stats_threadRunning, stats_threadTerminated;

	pthread_t ui_threadId;
	int ui_threadTerminate, ui_threadRunning, ui_threadTerminated;
	int trailerRow;

	/* PCAP */
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char *pcap_filter;

	/* list of discovered addresses and related statistics. */
	pthread_mutex_t lock;
	struct xorg_list list;

	/* File based statistics */
	char *file_prefix;
	int file_write_interval;
	time_t file_next_write_time;
};
static struct tool_context_s g_ctx = { 0 };
static struct tool_context_s *ctx = &g_ctx;

struct discovered_item_s
{
	struct xorg_list list;

	time_t firstSeen;
	time_t lastUpdated;
	struct ether_header ethhdr;
	struct iphdr iphdr;
	struct udphdr udphdr;

	/* PID Statistics */
	struct stream_statistics_s stats;

	/* File output */
	char filename[128];

	/* UI ASCII labels */
	char srcaddr[24];
	char dstaddr[24];
};

void discovered_item_free(struct discovered_item_s *di)
{
	free(di);
}

struct discovered_item_s *discovered_item_alloc(struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr)
{
	struct discovered_item_s *di = malloc(sizeof(*di));
	if (di) {
		time(&di->firstSeen);
		di->lastUpdated = di->firstSeen;
		memcpy(&di->ethhdr, ethhdr, sizeof(*ethhdr));
		memcpy(&di->iphdr, iphdr, sizeof(*iphdr));
		memcpy(&di->udphdr, udphdr, sizeof(*udphdr));

		struct in_addr dstaddr, srcaddr;
		srcaddr.s_addr = di->iphdr.saddr;
		dstaddr.s_addr = di->iphdr.daddr;

		sprintf(di->srcaddr, "%s:%d", inet_ntoa(srcaddr), ntohs(di->udphdr.uh_sport));
		sprintf(di->dstaddr, "%s:%d", inet_ntoa(dstaddr), ntohs(di->udphdr.uh_dport));
	}

	return di;
}

struct discovered_item_s *discovered_item_findcreate(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr)
{
	struct discovered_item_s *e = NULL, *found = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		
		if (e->iphdr.saddr != iphdr->saddr)
			continue;
		if (e->iphdr.daddr != iphdr->daddr)
			continue;
		if (e->udphdr.uh_sport != udphdr->uh_sport)
			continue;
		if (e->udphdr.uh_dport != udphdr->uh_dport)
			continue;

		found = e;
		break;
	}

	if (!found) {
		found = discovered_item_alloc(ethhdr, iphdr, udphdr);
		xorg_list_append(&found->list, &ctx->list);
	}
	pthread_mutex_unlock(&ctx->lock);

	return found;
}

static void discovered_item_console_summary(struct tool_context_s *ctx, struct discovered_item_s *di)
{
	char stream[128];
	sprintf(stream, "%s", di->srcaddr);
	sprintf(stream + strlen(stream), " -> %s", di->dstaddr);

	printf("   PID   PID     PacketCount     CCErrors    TEIErrors @ %6.2f : %s\n",
		di->stats.mbps, stream);
	printf("<---------------------------  ----------- ------------ ---Mb/ps------------------------------------------->\n");
	for (int i = 0; i < MAX_PID; i++) {
		if (di->stats.pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %12" PRIu64 " %12" PRIu64 "   %6.2f\n", i, i,
				di->stats.pids[i].packetCount,
				di->stats.pids[i].ccErrors,
				di->stats.pids[i].teiErrors,
				di->stats.pids[i].mbps);
		}
	}
}

static void discovered_items_console_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_console_summary(ctx, e);
	}
	pthread_mutex_unlock(&ctx->lock);
}

/* For a given item, open a stats file on disk, append the current stats, close it. */
static void discovered_item_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di)
{
	if (di->filename[0] == 0) {
		if (ctx->file_prefix)
			sprintf(di->filename, "%s/", ctx->file_prefix);

		sprintf(di->filename + strlen(di->filename), "%s", di->dstaddr);
	}

	int fd = open(di->filename, O_CREAT | O_RDWR | O_APPEND, 0644);
	if (fd < 0) {
		perror("open");
		return;
	}

	struct tm tm;
	time_t now;
	time(&now);
	localtime_r(&now, &tm);

	char line[256];
	char ts[24];
        sprintf(ts, "%04d%02d%02d-%02d%02d%02d",
                tm.tm_year + 1900,
                tm.tm_mon  + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec);

	sprintf(line, "time=%s,nic=%s,bps=%d,mbps=%.2f,tspacketcount=%" PRIu64 ",ccerrors=%" PRIu64 ",src=%s,dst=%s\n",
		ts,
		ctx->ifname,
		di->stats.pps * (188 * 8),
		di->stats.mbps,
		di->stats.packetCount,
		di->stats.ccErrors,
		di->srcaddr,
		di->dstaddr);

	write(fd, line, strlen(line));

	close(fd);
#if 0
	printf("   PID   PID     PacketCount     CCErrors    TEIErrors @ %6.2f : %s\n",
		di->stats.mbps, stream);
	printf("<---------------------------  ----------- ------------ ---Mb/ps------------------------------------------->\n");
	for (int i = 0; i < MAX_PID; i++) {
		if (di->stats.pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %12" PRIu64 " %12" PRIu64 "   %6.2f\n", i, i,
				di->stats.pids[i].packetCount,
				di->stats.pids[i].ccErrors,
				di->stats.pids[i].teiErrors,
				di->stats.pids[i].mbps);
		}
	}
#endif
}

static void discovered_items_file_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_file_summary(ctx, e);
	}
	pthread_mutex_unlock(&ctx->lock);
}

static void _processPackets(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr,
	const uint8_t *pkts, uint32_t pktCount)
{
	struct discovered_item_s *di = discovered_item_findcreate(ctx, ethhdr, iphdr, udphdr);

	pid_stats_update(&di->stats, pkts, pktCount);
}


static void pcap_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *pkt) 
{ 
	if (h->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return;

	struct ether_header *eth = (struct ether_header *)pkt;
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip = (struct iphdr *)((u_char *)eth + sizeof(struct ether_header));

		if (ip->protocol != IPPROTO_UDP)
			return;

		if (!IN_MULTICAST(ntohl(ip->daddr)))
			return;

		struct udphdr *udp = (struct udphdr *)((u_char *)ip + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udp + sizeof(struct udphdr));

		if (ctx->verbose) {
			struct in_addr dstaddr, srcaddr;
			srcaddr.s_addr = ip->saddr;
			dstaddr.s_addr = ip->daddr;
			printf("%s:%d -> %s:%d : %4d : %02x %02x %02x %02x\n",
				inet_ntoa(srcaddr), ntohs(udp->uh_sport),
				inet_ntoa(dstaddr), ntohs(udp->uh_dport),
				ntohs(udp->uh_ulen),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		if (ptr[0] != 0x47) {
			/* We don't currently deal with non-TS payload (RTP) */
		}

		/* TS Packet, almost certainly */
		/* We can safely assume there are len / 188 packets. */
		int pktCount = ntohs(udp->uh_ulen) / 188;
		_processPackets(ctx, eth, ip, udp, ptr, pktCount);
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
		sprintf(title_a, ctx->pcap_filter);
		char mask[64];
		sprintf(mask, "%s", inet_ntoa(ip_mask));
		sprintf(title_c, "NIC: %s (%s/%s)", ctx->ifname, inet_ntoa(ip_net), mask);
		int blen = 82 - (strlen(title_a) + strlen(title_c));
		memset(title_b, 0x20, sizeof(title_b));
		title_b[blen] = 0;

		attron(COLOR_PAIR(1));
		mvprintw( 0, 0, "%s%s%s", title_a, title_b, title_c);
		mvprintw( 1, 0, "<----------------------------------------------- M/BIT <------PACKETS <------CCErr");
		attroff(COLOR_PAIR(1));

		int streamCount = 1;
		struct discovered_item_s *di = NULL;
		pthread_mutex_lock(&ctx->lock);
		xorg_list_for_each_entry(di, &ctx->list, list) {

			mvprintw(streamCount + 2, 0, " %21s -> %21s %6.2f  %13" PRIu64 " %12" PRIu64 "",
				di->srcaddr,
				di->dstaddr,
				di->stats.mbps,
				di->stats.packetCount,
				di->stats.teiErrors,
				di->stats.ccErrors);
#if 0
			printf("<---------------------------  --------- ---------- ---Mb/ps------------------------>\n");
			for (int i = 0; i < MAX_PID; i++) {
				if (di->stats.pids[i].enabled) {
					printf("0x%04x (%4d) %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "   %6.2f\n", i, i,
						di->stats.pids[i].packetCount,
						di->stats.pids[i].ccErrors,
						di->stats.pids[i].teiErrors,
						di->stats.pids[i].mbps);
				}
			}
#endif
			streamCount++;
		}
		pthread_mutex_unlock(&ctx->lock);

		ctx->trailerRow = streamCount + 3;

		attron(COLOR_PAIR(2));
		mvprintw(ctx->trailerRow, 0, "q)uit");
		attroff(COLOR_PAIR(2));

		char tail_a[160], tail_b[160], tail_c[160];
		memset(tail_b, '-', sizeof(tail_b));
		sprintf(tail_a, "TSTOOLS_NIC_MONITOR");
		sprintf(tail_c, "%s", ctime(&now));
		blen = 83 - (strlen(tail_a) + strlen(tail_c));
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
		processed = pcap_dispatch(ctx->descr, -1, pcap_callback, NULL);
		if (processed == 0)
			usleep(5 * 1000);

		time(&now);
		if (ctx->file_prefix && ctx->file_next_write_time <= now) {
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
	printf("  -d <dir> Update file based stats in this target directory, every -n seconds.\n");
	printf("  -n <seconds> Interval to update -d file based stats [def: %d]\n", FILE_WRITE_INTERVAL);
	printf("  -f '<string>' Use a custom pcap filter. [def: '%s']\n", DEFAULT_PCAP_FILTER);
#if 0
	printf("  -o <output filename> (optional)\n");
#endif
}

int nic_monitor(int argc, char *argv[])
{
	int ch;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);
	ctx->file_write_interval = FILE_WRITE_INTERVAL;
	ctx->pcap_filter = DEFAULT_PCAP_FILTER;

	while ((ch = getopt(argc, argv, "?hd:F:i:t:vMn:")) != -1) {
		switch (ch) {
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

	ctx->descr = pcap_open_live(ctx->ifname, BUFSIZ, 1,-1, ctx->errbuf);
	if (ctx->descr == NULL) {
		fprintf(stderr, "Error, %s\n", ctx->errbuf);
		exit(1);
	}

	/* TODO: We should craft the filter to be udp dst 224.0.0.0/4 and then
	 * we don't need to manually filter in our callback.
	 */
	struct bpf_program fp;
	int ret = pcap_compile(ctx->descr, &fp, ctx->pcap_filter, 0, ctx->netp);
	if (ret == -1) {
		fprintf(stderr, "Error, pcap_compile\n");
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
	return 0;
}
