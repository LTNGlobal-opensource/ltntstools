
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ffmpeg-includes.h"

/* In string 'str', find occurences of character src and replace with character dst. */
/* return the number of substituions occured. */
int character_replace(char *str, char src, char dst)
{
	int c = 0;

	for (unsigned int i = 0; i < strlen(str); i++) {
		if (str[i] == src) {
			str[i] = dst;
			c++;
		}
	}

	return c;
}

int networkInterfaceExistsByName(const char *ifname)
{
	int exists = 0;

	/* Setup multicast on all IPV4 network interfaces, IPV6 interfaces are ignored */
	struct ifaddrs *addrs;
	int result = getifaddrs(&addrs);
	if (result >= 0) {
		const struct ifaddrs *cursor = addrs;
		while (cursor != NULL) {
#if 0
			char host[NI_MAXHOST];
			int r = getnameinfo(cursor->ifa_addr,
				cursor->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
				host, NI_MAXHOST,
				NULL, 0, NI_NUMERICHOST);
			printf("name: %s\n", cursor->ifa_name);
			printf("\t host: %s\n", host);
			if (cursor->ifa_flags & IFF_BROADCAST)
				printf("\tflags: IFF_BROADCAST = true\n");
			else
				printf("\tflags: IFF_BROADCAST = false\n");
			if (cursor->ifa_flags & IFF_UP)
				printf("\tflags: IFF_UP = true\n");
			else
				printf("\tflags: IFF_UP = false\n");
#endif
			if (/* (cursor->ifa_flags & IFF_BROADCAST) && */ (cursor->ifa_flags & IFF_UP) &&
				(cursor->ifa_addr) && 
				(cursor->ifa_addr->sa_family == AF_INET)) {

				char host[NI_MAXHOST];

				int r = getnameinfo(cursor->ifa_addr,
					cursor->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);
				if (r == 0) {
					if (strcmp(cursor->ifa_name, ifname) == 0) {
						exists = 1;
						break;
					}
				}
			}
			cursor = cursor->ifa_next;
		}
	}

	freeifaddrs(addrs);

	return exists;
}

int networkInterfaceExistsByAddress(const char *ipaddress)
{
	int exists = 0;

	/* Setup multicast on all IPV4 network interfaces, IPV6 interfaces are ignored */
	struct ifaddrs *addrs;
	int result = getifaddrs(&addrs);
	if (result >= 0) {
		const struct ifaddrs *cursor = addrs;
		while (cursor != NULL) {
			if (/* (cursor->ifa_flags & IFF_BROADCAST) && */ (cursor->ifa_flags & IFF_UP) &&
				(cursor->ifa_addr) && 
				(cursor->ifa_addr->sa_family == AF_INET)) {

				char host[NI_MAXHOST];

				int r = getnameinfo(cursor->ifa_addr,
					cursor->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);
				if (r == 0) {
					if (strcmp(ipaddress, host) == 0) {
						exists = 1;
						break;
					}
				}
			}
			cursor = cursor->ifa_next;
		}
	}

	freeifaddrs(addrs);

	return exists;
}

void networkInterfaceList()
{
	/* Setup multicast on all IPV4 network interfaces, IPV6 interfaces are ignored */
	struct ifaddrs *addrs;
	int result = getifaddrs(&addrs);
	if (result >= 0) {
		const struct ifaddrs *cursor = addrs;
		while (cursor != NULL) {
			if (/* (cursor->ifa_flags & IFF_BROADCAST) && */ (cursor->ifa_flags & IFF_UP) &&
				(cursor->ifa_addr) &&
				(cursor->ifa_addr->sa_family == AF_INET)) {

				char host[NI_MAXHOST];

				int r = getnameinfo(cursor->ifa_addr,
					cursor->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);
				if (r == 0) {
					printf("\t%s : %s\n", cursor->ifa_name, host);
				}
			}
			cursor = cursor->ifa_next;
		}
	}

	freeifaddrs(addrs);
}

int network_addr_compare(
	struct iphdr *src_iphdr, struct udphdr *src_udphdr,
	struct iphdr *dst_iphdr, struct udphdr *dst_udphdr)
{
#ifdef __APPLE__
	if (src_iphdr->ip_src.s_addr != dst_iphdr->ip_src.s_addr)
		return 0;
	if (src_iphdr->ip_dst.s_addr != dst_iphdr->ip_dst.s_addr)
		return 0;
	if (src_udphdr->uh_sport != dst_udphdr->uh_sport)
		return 0;
	if (src_udphdr->uh_dport != dst_udphdr->uh_dport)
		return 0;
#endif
#ifdef __linux__
	if (src_iphdr->saddr != dst_iphdr->saddr)
		return 0;
	if (src_iphdr->daddr != dst_iphdr->daddr)
		return 0;
	if (src_udphdr->source != dst_udphdr->source)
		return 0;
	if (src_udphdr->dest != dst_udphdr->dest)
		return 0;
#endif

	return 1; /* Success, matched */
}

char *network_stream_ascii(struct iphdr *iphdr, struct udphdr *udphdr)
{
	struct in_addr dstaddr, srcaddr;
#ifdef __linux__
	srcaddr.s_addr = iphdr->saddr;
	dstaddr.s_addr = iphdr->daddr;
#endif
#ifdef __APPLE__
	srcaddr.s_addr = iphdr->ip_src.s_addr;
	dstaddr.s_addr = iphdr->ip_dst.s_addr;
#endif

	char *str = malloc(256);
#ifdef __linux__
	sprintf(str, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->source));
	sprintf(str + strlen(str), " -> %s:%d", inet_ntoa(dstaddr), ntohs(udphdr->dest));
#endif
#ifdef __APPLE__
	sprintf(str, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->uh_sport));
	sprintf(str + strlen(str), " -> %s:%d", inet_ntoa(dstaddr), ntohs(udphdr->uh_dport));
#endif

	return str;
}

int isValidTransportFile(const char *filename)
{
	struct stat buf;

	if (stat(filename, &buf) == 0) {
		if (S_ISREG(buf.st_mode) && buf.st_blocks) {
			/* Regular file with some length */
			return 1;
		}
	}

	return 0;
}

int process_memory_init(struct statm_context_s *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->initialized = 1;

	return 0; /* Success */
}

int process_memory_update(struct statm_context_s *ctx, int collectInterval)
{
	const char *statm_path = "/proc/self/statm";

	if (!ctx->initialized)
		return -1;

	time_t now = time(NULL);
	if (ctx->lastCollectTime + collectInterval > now) {
		/* Too soon to collect */
		return 0;
	}
	ctx->lastCollectTime = now;

	FILE *f = fopen(statm_path,"r");
	if (!f){
		return -2;
	}

	struct statm_s *s = &ctx->curr;

	int ret = fscanf(f, "%ld %ld %ld %ld %ld %ld %ld",
    	&s->size,
		&s->resident,
		&s->share,
		&s->text,
		&s->lib,
		&s->data,
		&s->dt);

	if (ret != 7) {
		perror(statm_path);
		return -3;
	}

	if (ctx->startTime == 0) {
		ctx->startTime = time(NULL);
		ctx->startup = ctx->curr;
	}
	fclose(f);

	return 0; /* Success */
}

int process_memory_dprintf(int fd, struct statm_context_s *ctx, int reportSeconds)
{
/* The columns are:

              size       total program size
                         (same as VmSize in /proc/[pid]/status)
              resident   resident set size
                         (same as VmRSS in /proc/[pid]/status)
              share      shared pages (from shared mappings)
              text       text (code)
              lib        library (unused in Linux 2.6)
              data       data + stack
              dt         dirty pages (unused in Linux 2.6)
*/
	if (!ctx->initialized)
		return -1;

	time_t now = time(NULL);
	if (ctx->lastReportTime + reportSeconds > now) {
		/* Too soon to consoile report */
		return 0;
	}
	ctx->lastReportTime = now;

	char ts[80];
	sprintf(ts, "%s", ctime(&now));
	ts[ strlen(ts) - 1] = 0;

	struct statm_s *s = &ctx->startup;
	struct statm_s *c = &ctx->curr;

#if 0
	/* Report current memory sizes plus and any growth since startup */
	dprintf(fd, "%s: pid %d, size %ld (%.0f%%), resident %ld (%.0f%%), share %ld (%.0f%%), text %ld (%.0f%%), lib %ld (%.0f%%), data %ld (%.0f%%), dt %ld (%.0f%%)\n",
		ts,
		getpid(),
		c->size,     (((double)c->size - (double)s->size) / (double)s->size) * 100.0,
		c->resident, (((double)c->resident - (double)s->resident) / (double)s->resident) * 100.0,
		c->share,    (((double)c->share - (double)s->share) / (double)s->share) * 100.0,
		c->text,     (((double)c->text - (double)s->text) / (double)s->text) * 100.0,
		c->lib,      (((double)c->lib - (double)s->lib) / (double)s->lib) * 100.0,
		c->data,     (((double)c->data - (double)s->data) / (double)s->data) * 100.0,
		c->dt,       (((double)c->dt - (double)s->dt) / (double)s->dt) * 100.0);
#else
	/* Report current memory sizes plus and any growth since startup */
	dprintf(fd, "%s: pid %d, size %ld (%.0f%% growth)\n",
		ts,
		getpid(),
		c->size,     (((double)c->size - (double)s->size) / (double)s->size) * 100.0);
#endif

	return 0; /* Success */
}

int process_memory_sprintf(char *dst, struct statm_context_s *ctx, int reportSeconds, int includeTimestamp)
{
	if (!ctx->initialized)
		return -1;

	time_t now = time(NULL);
	if (ctx->lastReportTime + reportSeconds > now) {
		/* Too soon to consoile report */
		return 0;
	}
	ctx->lastReportTime = now;

	struct statm_s *s = &ctx->startup;
	struct statm_s *c = &ctx->curr;

	if (includeTimestamp) {
		char ts[80];
		sprintf(ts, "%s", ctime(&now));
		ts[ strlen(ts) - 1] = 0;

		/* Report current memory sizes plus and any growth since startup */
		sprintf(dst, "%s: pid %d, size %ld (%.0f%% growth)\n",
			ts,
			getpid(),
			c->size,     (((double)c->size - (double)s->size) / (double)s->size) * 100.0);
	} else {
		sprintf(dst, "pid %d, size %ld (%.0f%% growth)\n",
			getpid(),
			c->size,     (((double)c->size - (double)s->size) / (double)s->size) * 100.0);
	}

	return 0; /* Success */
}

/* Subtract N ms from a timestamp, to find a time prior to now */
/* Never pass a value in ms more than one second */
void subtract_ms_from_timeval(struct timeval *result, struct timeval *now, unsigned int ms)
{
	result->tv_sec = now->tv_sec;
	result->tv_usec = now->tv_usec;

	if (result->tv_usec < (ms * 1000)) {
		result->tv_usec += (1000 * 1000);
		result->tv_sec--;
	}
	
	result->tv_usec -= (ms * 1000);
}

int ISO8601_UTC_CreateTimestamp(struct timeval *tv, char **dst)
{
    struct timeval curTime;
	if (tv)
		curTime = *tv;
	else
		gettimeofday(&curTime, NULL);

	if (dst == NULL)
		return -1;

	int x = curTime.tv_usec / 1000;

	char *buf = malloc(sizeof "2023-10-16T07:07:09.000Z    ");
	char *p = buf + strftime(buf, sizeof("2023-10-16T07:07:09.000Z    "), "%FT%T", gmtime(&curTime.tv_sec));
	sprintf(p, ".%03dZ", x);

	*dst = buf;

    return 0;
}

void printToolBanner(char *toolname, char *version)
{
	if ((!toolname) || (!version))
		return;

	char ts[256] = { 0 };

	time_t now = time(0);
	sprintf(ts, "%s", ctime(&now));
	ts[ strlen(ts) - 1] = 0;

	printf("%s: %s %s\n", ts, toolname, version);

	char *name = (char *)calloc(1, 4096);
	if (!name)
		return;

	int fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd == -1) {
		free(name);
		return;
	}

	int size = read(fd, name, 4096);
	close(fd);
	
	for(int i = 0 ; i < size; i++) {
		if (!name[i])
			name[i] = ' ';
	}

	printf("%s: %s\n", ts, name);

	free(name);
}

int ltntstools_file_estimate_bitrate(const char *filename, uint32_t *bps)
{
	if (!filename || !bps)
		return -1;

	/* Figure out the PCR Pid */
	struct ltntstools_pat_s *pat;
	if (ltntstools_streammodel_alloc_from_url(filename, &pat) < 0) {
		fprintf(stderr, "%s() Unable to query stream model for file\n", __func__);
		return -1;
	}

	int e = 0;
	struct ltntstools_pmt_s *pmt;
	if (ltntstools_pat_enum_services_video(pat, &e, &pmt) < 0) {
		fprintf(stderr, "%s() Unable to detect PCR PID from file.\n", __func__);
		return -1;
	}

	FILE *fh = fopen(filename, "rb");
	if (!fh) {
		ltntstools_pat_free(pat);
		return -1;
	}

	int rlen = 32 * 1048576;
	uint8_t *buf = malloc(rlen);
	if (!buf) {
		ltntstools_pat_free(pat);
		return -1;
	}

	int l = fread(buf, 1, rlen, fh);
	if (l > 0) {
		int arrayLength;
		struct ltntstools_pcr_position_s *array;
		if (ltntstools_queryPCRs(buf, l, 0, &array, &arrayLength) < 0) {
			fclose(fh);
			free(buf);
			ltntstools_pat_free(pat);
			return -1;
		}

		struct ltntstools_pcr_position_s first = { 0 }, next = { 0 };
		first.pid = 0;

		for (int i = 0; i < arrayLength; i++) {
			struct ltntstools_pcr_position_s *p = &array[i];
			if (p->pid != pmt->PCR_PID)
				continue;

			if (first.pid == 0)
				first = *p;

			next = *p;
		}

#if 0
		printf("first   offset %12" PRIu64 "  scr %14" PRIu64 "\n", first.offset, first.pcr);
		printf(" next   offset %12" PRIu64 "  scr %14" PRIu64 "\n", next.offset, next.pcr);
#endif
		uint64_t bits = (next.offset - first.offset) * 8;
		uint64_t ticks_ms = (next.pcr - first.pcr) / 27000;
		*bps = (bits / ticks_ms) * 1000;
#if 0
		printf("  time %14" PRIu64 " (ms)\n", ticks_ms);
		printf("  bits %14" PRIu64 "\n", bits);
		printf("   bps %14d\n", *bps);
#endif
	}

	fclose(fh);
	free(buf);
	ltntstools_pat_free(pat);

	return 0; /* Success */
}

int ltntstools_streammodel_alloc_from_url(const char *url, struct ltntstools_pat_s **pat)
{
	void *sm;
	*pat = NULL;

	if (ltntstools_streammodel_alloc(&sm, NULL) < 0) {
		fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
		return -1;
	}

	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, url, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		ltntstools_streammodel_free(sm);
		fprintf(stderr, "%s() url '%s' syntax error\n", __func__, url);
		return -1;
	}

	uint8_t buf[7 * 188];
	int ok = 1;
	while (ok) {
		int rlen = avio_read(puc, &buf[0], sizeof(buf));
		if (rlen == -EAGAIN) {
			usleep(2 * 1000);
			continue;
		}
		if (rlen < 0)
			break;

		int complete = 0;
		struct timeval now;
		gettimeofday(&now, NULL);
		ltntstools_streammodel_write(sm, &buf[0], rlen / 188, &complete, &now);

		if (complete) {

			struct ltntstools_pat_s *m = NULL;
			if (ltntstools_streammodel_query_model(sm, &m) == 0) {
				*pat = m;
			}
			break;
		}

	}
	avio_close(puc);

	if (0 && *pat) {
		ltntstools_pat_dprintf(*pat, 0);
	}

	ltntstools_streammodel_free(sm);
	
	if (*pat == NULL)
		return -1; /* Error */

	return 0; /* Success */
}

