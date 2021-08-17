
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

int character_replace(char *str, char src, char dst);
void networkInterfaceList();
int  networkInterfaceExists(const char *ifname);

/* For a given src and dst ip and udp hheaders, determine
 * of they're an identical stream by matching address and port only.
 * Return is boolean
 */
int network_addr_compare(
	struct iphdr *src_iphdr, struct udphdr *src_udphdr,
	struct iphdr *dst_iphdr, struct udphdr *dst_udphdr);

char *network_stream_ascii(struct iphdr *iphdr, struct udphdr *udphdr);

#endif  /* LTNTOOLS_UTILS_H */
