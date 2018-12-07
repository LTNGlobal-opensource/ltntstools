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

static int gRunning = 0;

struct tool_context_s
{
	char *ifname;
	int verbose;

	pthread_t threadId;
	int threadTerminate, threadRunning, threadTerminated;

	/* PCAP */
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;

	/* list of discovered addresses and related statistics. */
	pthread_mutex_t lock;
	struct xorg_list list;
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
	struct in_addr addr;
	addr.s_addr = di->iphdr.daddr;
	printf("   PID   PID     PacketCount   CCErrors  TEIErrors @ %6.2f : %s:%d\n",
		di->stats.mbps,
		inet_ntoa(addr), ntohs(di->udphdr.uh_dport));
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
			struct in_addr addr;
			addr.s_addr = ip->daddr;
			printf("%s:%d : %4d : %02x %02x %02x %02x\n", inet_ntoa(addr), ntohs(udp->uh_dport),
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

static void *thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->threadRunning = 1;
	ctx->threadTerminate = 0;
	ctx->threadTerminated = 0;

	while (!ctx->threadTerminate) {
		pcap_dispatch(ctx->descr, -1, pcap_callback, NULL);
	}
	ctx->threadTerminated = 1;

	return 0;
}

static void signal_handler(int signum)
{
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
#if 0
	printf("  -M Display an interactive console with stats.\n");
	printf("  -o <output filename> (optional)\n");
#endif
}

int nic_monitor(int argc, char *argv[])
{
	int ch;

	pthread_mutex_init(&ctx->lock, NULL);
	xorg_list_init(&ctx->list);

	while ((ch = getopt(argc, argv, "?hi:v")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->ifname = optarg;
			break;
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->ifname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\nError, -i is mandatory.\n");
		exit(1);
	}

	printf("  iface: %s\n", ctx->ifname);

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	pcap_lookupnet(ctx->ifname, &netp, &maskp, ctx->errbuf);

	struct in_addr ip_net, ip_mask;
	ip_net.s_addr = netp;
	ip_mask.s_addr = maskp;
	printf("network: %s\n", inet_ntoa(ip_net));
	printf("   mask: %s\n", inet_ntoa(ip_mask));

	ctx->descr = pcap_open_live(ctx->ifname, BUFSIZ, 1,-1, ctx->errbuf);
	if (ctx->descr == NULL) {
		fprintf(stderr, "Error, %s\n", ctx->errbuf);
		exit(1);
	}

	struct bpf_program fp;
	int ret = pcap_compile(ctx->descr, &fp, "ip", 0, netp);
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

	/* Start any threads, main loop processes keybaord. */
	signal(SIGINT, signal_handler);

	gRunning = 1;
	pthread_create(&ctx->threadId, 0, thread_func, ctx);

	while (gRunning) {
		int ch = getch();
		if (ch == 'q')
			break;
		usleep(250 * 1000);
	}

	printf("user quit loop\n");

	/* Shutdown ffmpeg */
	ctx->threadTerminate = 1;
	while (!ctx->threadTerminated)
		usleep(50 * 1000);

	discovered_items_console_summary(ctx);

	return 0;
}
