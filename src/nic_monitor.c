#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <curses.h>
#include <inttypes.h>
#include <pthread.h>
#include <libltntstools/ltntstools.h>
#include "xorg-list.h"
#include "parsers.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define DEFAULT_TRAILERROW 18
#define FILE_WRITE_INTERVAL 5
#define DEFAULT_PCAP_FILTER "udp dst portrange 4000-4999"

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
	int snaplen;
	int bufferSize;

	/* list of discovered addresses and related statistics. */
	pthread_mutex_t lock;
	struct xorg_list list;

	/* File based statistics */
	char *file_prefix;
	int file_write_interval;
	time_t file_next_write_time;

	/* Detailed file based statistics */
	char *detailed_file_prefix;
};
static struct tool_context_s g_ctx = { 0 };
static struct tool_context_s *ctx = &g_ctx;

struct discovered_item_s
{
	struct xorg_list list;

	time_t firstSeen;
	time_t lastUpdated;
	struct ether_header ethhdr;
#ifdef __APPLE__
#define iphdr ip
	struct ip iphdr;
#endif
#ifdef __linux__
	struct iphdr iphdr;
#endif
	struct udphdr udphdr;

	/* PID Statistics */
	struct ltntstools_stream_statistics_s stats;

	/* File output */
	char filename[128];
	char detailed_filename[128];

	/* UI ASCII labels */
	char srcaddr[24];
	char dstaddr[24];

	int isRTP;

	/* IAT */
	int iat_lwm_us; /* IAT low watermark (us), measurement of UDP receive interval */
	int iat_hwm_us; /* IAT high watermark (us), measurement of UDP receive interval */
	int iat_cur_us; /* IAT current measurement (us) */
	struct timeval iat_last_frame; /* Timestamp of last UDP frame for this entity. */
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
#ifdef __linux__
		srcaddr.s_addr = di->iphdr.saddr;
		dstaddr.s_addr = di->iphdr.daddr;
#endif
#ifdef __APPLE__
		srcaddr.s_addr = di->iphdr.ip_src.s_addr;
		dstaddr.s_addr = di->iphdr.ip_dst.s_addr;
#endif

		sprintf(di->srcaddr, "%s:%d", inet_ntoa(srcaddr), ntohs(di->udphdr.uh_sport));
		sprintf(di->dstaddr, "%s:%d", inet_ntoa(dstaddr), ntohs(di->udphdr.uh_dport));

		di->iat_lwm_us = 50000000;
		di->iat_hwm_us = -1;
		di->iat_cur_us = 0;
	}

	return di;
}

struct discovered_item_s *discovered_item_findcreate(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr)
{
	struct discovered_item_s *e = NULL, *found = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {

#ifdef __APPLE__
		if (e->iphdr.ip_src.s_addr != iphdr->ip_src.s_addr)
			continue;
		if (e->iphdr.ip_dst.s_addr != iphdr->ip_dst.s_addr)
			continue;
#endif
#ifdef __linux__
		if (e->iphdr.saddr != iphdr->saddr)
			continue;
		if (e->iphdr.daddr != iphdr->daddr)
			continue;
#endif
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

static void discovered_item_fd_summary(struct tool_context_s *ctx, struct discovered_item_s *di, int fd)
{
	char stream[128];
	sprintf(stream, "%s", di->srcaddr);
	sprintf(stream + strlen(stream), " -> %s", di->dstaddr);

	dprintf(fd, "   PID   PID     PacketCount     CCErrors    TEIErrors @ %6.2f : %s (%s)\n",
		ltntstools_pid_stats_stream_get_mbps(&di->stats), stream,
		di->isRTP ? "RTP" : "UDP");
	dprintf(fd, "<---------------------------  ----------- ------------ ---Mb/ps------------------------------------------------>\n");
	for (int i = 0; i < MAX_PID; i++) {
		if (di->stats.pids[i].enabled) {
			dprintf(fd, "0x%04x (%4d) %14" PRIu64 " %12" PRIu64 " %12" PRIu64 "   %6.2f\n", i, i,
				di->stats.pids[i].packetCount,
				di->stats.pids[i].ccErrors,
				di->stats.pids[i].teiErrors,
				ltntstools_pid_stats_pid_get_mbps(&di->stats, i));
		}
	}
}

static void discovered_items_console_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_fd_summary(ctx, e, STDOUT_FILENO);
	}
	pthread_mutex_unlock(&ctx->lock);
}

/* For a given item, open a detailed stats file on disk, append the current stats, close it. */
static void discovered_item_detailed_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di)
{
	if (di->detailed_filename[0] == 0) {
		if (ctx->detailed_file_prefix)
			sprintf(di->detailed_filename, "%s", ctx->detailed_file_prefix);

		sprintf(di->detailed_filename + strlen(di->detailed_filename), "%s", di->dstaddr);
	}

	int fd = open(di->detailed_filename, O_CREAT | O_RDWR | O_APPEND, 0644);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", di->detailed_filename);
		return;
	}

	/* If we're a super user, obtain any SUDO uid and change file ownership to it - if possible. */
	if (getuid() == 0 && getenv("SUDO_UID") && getenv("SUDO_GID")) {
		uid_t o_uid = atoi(getenv("SUDO_UID"));
		gid_t o_gid = atoi(getenv("SUDO_GID"));

		if (fchown(fd, o_uid, o_gid) != 0) {
			/* Error */
			fprintf(stderr, "Error changing %s ownership to uid %d gid %d, ignoring\n",
				di->detailed_filename, o_uid, o_gid);
		}
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
		ltntstools_pid_stats_stream_get_bps(&di->stats),
		ltntstools_pid_stats_stream_get_mbps(&di->stats),
		di->stats.packetCount,
		di->stats.ccErrors,
		di->srcaddr,
		di->dstaddr);

	write(fd, line, strlen(line));

	discovered_item_fd_summary(ctx, di, fd);

	close(fd);
}

/* For a given item, open a stats file on disk, append the current stats, close it. */
static void discovered_item_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di)
{
	if (di->filename[0] == 0) {
		if (ctx->file_prefix)
			sprintf(di->filename, "%s", ctx->file_prefix);

		sprintf(di->filename + strlen(di->filename), "%s", di->dstaddr);
	}

	if (di->detailed_filename[0] == 0) {
		if (ctx->detailed_file_prefix)
			sprintf(di->detailed_filename, "%s", ctx->detailed_file_prefix);

		sprintf(di->detailed_filename + strlen(di->detailed_filename), "%s", di->dstaddr);
	}

	int fd = open(di->filename, O_CREAT | O_RDWR | O_APPEND, 0644);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", di->filename);
		return;
	}

	/* If we're a super user, obtain any SUDO uid and change file ownership to it - if possible. */
	if (getuid() == 0 && getenv("SUDO_UID") && getenv("SUDO_GID")) {
		uid_t o_uid = atoi(getenv("SUDO_UID"));
		gid_t o_gid = atoi(getenv("SUDO_GID"));

		if (fchown(fd, o_uid, o_gid) != 0) {
			/* Error */
			fprintf(stderr, "Error changing %s ownership to uid %d gid %d, ignoring\n",
				di->filename, o_uid, o_gid);
		}
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
		ltntstools_pid_stats_stream_get_bps(&di->stats),
		ltntstools_pid_stats_stream_get_mbps(&di->stats),
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
		discovered_item_detailed_file_summary(ctx, e);
	}
	pthread_mutex_unlock(&ctx->lock);
}

static void discovered_items_stats_reset(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		ltntstools_pid_stats_reset(&e->stats);
		e->iat_lwm_us = 5000000;
		e->iat_hwm_us = -1;
		e->iat_lwm_us = 0;
	}
	pthread_mutex_unlock(&ctx->lock);
}

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
		sprintf(title_c, "NIC: %s (%s/%s)", ctx->ifname, inet_ntoa(ip_net), mask);
		int blen = 108 - (strlen(title_a) + strlen(title_c));
		memset(title_b, 0x20, sizeof(title_b));
		title_b[blen] = 0;

		attron(COLOR_PAIR(1));
		mvprintw( 0, 0, "%s%s%s", title_a, title_b, title_c);
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

#if 1
	ctx->descr = pcap_create(ctx->ifname, ctx->errbuf);
#else
#ifdef __linux__
	ctx->descr = pcap_open_live(ctx->ifname, ctx->snaplen, 1,-1, ctx->errbuf);
#endif
#ifdef __APPLE__
	ctx->descr = pcap_open_live(ctx->ifname, 65535, 1, 1, ctx->errbuf);
#endif
#endif
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
