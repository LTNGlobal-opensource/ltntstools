/* Extract TS packets form UDP/RTP/MPEG-TS pcap files */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

static FILE *ofh = NULL;
static int count = 0;
static char *addr = NULL;
static int port = 0;
static int verbose = 0;
static struct sockaddr_in sa;

static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
        for (unsigned int i = 0; i < len; i++)
                printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
        printf("\n");
}

static void pkt_handler(u_char *tmp, struct pcap_pkthdr *hdr, u_char *buf)
{
	if (verbose) {
		printf("%" PRIu64 ":%" PRIu64 " (%" PRIu64 ")\n",
			(uint64_t)hdr->ts.tv_sec, (uint64_t)hdr->ts.tv_usec, (uint64_t)hdr->len);
	}
	if (verbose > 1) {
		hexdump(buf, 32, 32);
	}

	struct udphdr *udp = NULL;
#if defined(__linux__)
	struct iphdr *ip = NULL;
#endif
#if defined(__APPLE__)
	struct ip *ip = NULL;
#endif
	int hdrlen = 0;

	uint32_t *x = (uint32_t *)buf;
	if (*x == 2) {
		/* Loopback capture */
#if defined(__linux__)
		ip = (struct iphdr *)(buf + 4);
		udp = (struct udphdr *)(buf + 4 + sizeof(struct iphdr));
		hdrlen = 4 + sizeof(struct iphdr) + sizeof(struct udphdr);
#endif
#if defined(__APPLE__)
		ip = (struct ip *)(buf + 4);
		udp = (struct udphdr *)(buf + 4 + sizeof(struct ip));
		hdrlen = 4 + sizeof(struct ip) + sizeof(struct udphdr);
#endif
	}

	if ((!ip) || (!udp))
		return;

	uint8_t *data = buf + hdrlen;
	uint32_t len = hdr->len - hdrlen;

	if (ntohs(udp->uh_dport) != port)
		return;

#if defined(__linux__)
	if (ip->daddr != sa.sin_addr.s_addr)
#endif
#if defined(__APPLE__)
	if (ip->ip_dst.s_addr != sa.sin_addr.s_addr)
#endif
		return;

	if (verbose) {
	}
	count++;
	if (*data != 0x47) {
		fprintf(stderr, "Error at packet %d\n", count);
		hexdump(data, len, 16);
		exit(1);
	}

	if (ofh)
		fwrite(data, 1, len, ofh);
}

static void _usage(const char *prog)
{
	printf("Usage: %s\n", prog);
	printf("  -i <input.pcap>\n");
	printf("  -o <output.ts>\n");
	printf("  -a <ip address Eg. 234.1.1.1>\n");
	printf("  -p <ip port Eg. 9200>\n");
	printf("  -v increase verbosity level\n");
}

int pcap2ts(int argc, char* argv[])
{
	int ch;
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *iname = NULL, *oname = NULL;

	while ((ch = getopt(argc, argv, "?hi:o:a:p:v")) != -1) {
		switch(ch) {
		case 'a':
			addr = optarg;
			if (inet_pton(AF_INET, optarg, &(sa.sin_addr)) != 1) {
				_usage(argv[0]);
				fprintf(stderr, "\n *** -a is malformed ***\n");
				exit(1);
			}
			break;
		case 'i':
			iname = optarg;
			break;
		case 'o':
			oname = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		case '?':
		default:
			_usage(argv[0]);
			exit(1);
		}
	}

	if (!iname) {
		_usage(argv[0]);
		fprintf(stderr, "\n *** -i is mandatory ***\n");
		exit(1);
	}

	if (!port) {
		_usage(argv[0]);
		fprintf(stderr, "\n *** -p is mandatory ***\n");
		exit(1);
	}

	if (!addr) {
		_usage(argv[0]);
		fprintf(stderr, "\n *** -a is mandatory ***\n");
		exit(1);
	}

	if (oname) {
		ofh = fopen(oname, "wb");
		if (!ofh) {
			fprintf(stderr, "Cannot open output file %s\n", oname);
			exit(1);
		}
	}

	if ((pcap = pcap_open_offline(iname, errbuf)) == NULL) {
		fprintf(stderr, "Cannot open pcap file: %s\n", errbuf); 
		exit(1);
	}

	printf("Extracting TS from %s:%d\n", addr, port);

	if ((pcap_loop(pcap, -1, (void*)pkt_handler, NULL)) != 0) {
		fprintf(stderr, "Cannot read from pcap file: %s\n", pcap_geterr(pcap)); 
		exit(1);
	}
	pcap_close(pcap);

	if (ofh)
		fclose(ofh);

	return 0;
}
