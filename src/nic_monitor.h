#ifndef NIC_MONITOR_H
#define NIC_MONITOR_H

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
	struct pcap_stat pcap_stats; /* network loss and drop statistics */

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

#endif /* NIC_MONITOR_H */
