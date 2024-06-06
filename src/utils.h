
#ifndef LTNTOOLS_UTILS_H
#define LTNTOOLS_UTILS_H

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#ifdef __APPLE__
#define iphdr ip
#endif

/* Caller must free the return object */
int ISO8601_UTC_CreateTimestamp(struct timeval *tv, char **dst);

int character_replace(char *str, char src, char dst);
void networkInterfaceList();
int  networkInterfaceExistsByName(const char *ifname);
int  networkInterfaceExistsByAddress(const char *ipaddress);

/* For a given src and dst ip and udp hheaders, determine
 * of they're an identical stream by matching address and port only.
 * Return is boolean
 */
int network_addr_compare(
	struct iphdr *src_iphdr, struct udphdr *src_udphdr,
	struct iphdr *dst_iphdr, struct udphdr *dst_udphdr);

char *network_stream_ascii(struct iphdr *iphdr, struct udphdr *udphdr);

int isValidTransportFile(const char *filename);

struct statm_s
{
    unsigned long size;
	unsigned long resident;
	unsigned long share;
	unsigned long text;
	unsigned long lib;
	unsigned long data;
	unsigned long dt;
};

struct statm_context_s
{
	int initialized;
	time_t startTime;
	time_t lastReportTime;
	time_t lastCollectTime;
	struct statm_s startup;
	struct statm_s curr;
};

int process_memory_init(struct statm_context_s *ctx);
int process_memory_update(struct statm_context_s *ctx, int collectInterval);
int process_memory_dprintf(int fd, struct statm_context_s *ctx, int reportSeconds);
int process_memory_sprintf(char *dst, struct statm_context_s *ctx, int reportSeconds, int includeTimestamp);

void subtract_ms_from_timeval(struct timeval *result, struct timeval *now, unsigned int ms);

#endif  /* LTNTOOLS_UTILS_H */
