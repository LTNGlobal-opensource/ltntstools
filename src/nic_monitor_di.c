
#include "nic_monitor.h"

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

void discovered_item_fd_summary(struct tool_context_s *ctx, struct discovered_item_s *di, int fd)
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

void discovered_items_console_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_fd_summary(ctx, e, STDOUT_FILENO);
	}
	pthread_mutex_unlock(&ctx->lock);
}

/* For a given item, open a detailed stats file on disk, append the current stats, close it. */
void discovered_item_detailed_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di)
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
void discovered_item_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di)
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

void discovered_items_file_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_file_summary(ctx, e);
		discovered_item_detailed_file_summary(ctx, e);
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_stats_reset(struct tool_context_s *ctx)
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

void discovered_item_state_set(struct discovered_item_s *di, unsigned int state)
{
	di->state |= state;
}

void discovered_item_state_clr(struct discovered_item_s *di, unsigned int state)
{
	di->state &= (~state);
}

unsigned int discovered_item_state_get(struct discovered_item_s *di, unsigned int state)
{
	return di->state & state;
}

