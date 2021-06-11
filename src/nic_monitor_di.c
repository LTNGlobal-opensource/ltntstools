
#include "nic_monitor.h"

void discovered_item_free(struct discovered_item_s *di)
{
	if (di->pcapRecorder) {
		ltntstools_segmentwriter_free(di->pcapRecorder);
		di->pcapRecorder = NULL;
	}

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

/* This function is take with the ctx->list held by the caller. */
static void discovered_item_insert(struct tool_context_s *ctx, struct discovered_item_s *di)
{
	struct discovered_item_s *e = NULL;

	/* Maintain a sorted list of objects, based on dst ip address and port. */
	xorg_list_for_each_entry(e, &ctx->list, list) {
#ifdef __linux__
		uint64_t a = (uint64_t)ntohl(e->iphdr.daddr) << 16;
		a |= (e->udphdr.uh_dport);

		uint64_t b = (uint64_t)ntohl(di->iphdr.daddr) << 16;
		b |= (di->udphdr.uh_dport);
#endif
		if (a < b)
			continue;

		if (a == b) {
			discovered_item_state_set(di, DI_STATE_DST_DUPLICATE);
			discovered_item_state_set(e, DI_STATE_DST_DUPLICATE);
		}
		xorg_list_add(&di->list, e->list.prev);
		return;
	}

	xorg_list_append(&di->list, &ctx->list);
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
		discovered_item_insert(ctx, found);
		if (ctx->automaticallyRecordStreams) {
			discovered_item_state_set(found, DI_STATE_PCAP_RECORD_START);
		}
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

	sprintf(line, "time=%s,nic=%s,bps=%d,mbps=%.2f,tspacketcount=%" PRIu64 ",ccerrors=%" PRIu64 ",src=%s,dst=%s,dropped=%d/%d\n",
		ts,
		ctx->ifname,
		ltntstools_pid_stats_stream_get_bps(&di->stats),
		ltntstools_pid_stats_stream_get_mbps(&di->stats),
		di->stats.packetCount,
		di->stats.ccErrors,
		di->srcaddr,
		di->dstaddr,
		ctx->pcap_stats.ps_drop,
		ctx->pcap_stats.ps_ifdrop);

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

	sprintf(line, "time=%s,nic=%s,bps=%d,mbps=%.2f,tspacketcount=%" PRIu64 ",ccerrors=%" PRIu64 ",src=%s,dst=%s,dropped=%d/%d\n",
		ts,
		ctx->ifname,
		ltntstools_pid_stats_stream_get_bps(&di->stats),
		ltntstools_pid_stats_stream_get_mbps(&di->stats),
		di->stats.packetCount,
		di->stats.ccErrors,
		di->srcaddr,
		di->dstaddr,
		ctx->pcap_stats.ps_drop,
		ctx->pcap_stats.ps_ifdrop);

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
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_item_state_set(struct discovered_item_s *di, unsigned int state)
{
	di->state |= state;
}

void discovered_item_state_clr(struct discovered_item_s *di, unsigned int state)
{
	di->state &= ~(state);
}

unsigned int discovered_item_state_get(struct discovered_item_s *di, unsigned int state)
{
	return di->state & state;
}

void discovered_items_select_first(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_state_set(e, DI_STATE_SELECTED);
		break;
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_next(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	int doSelect = 0;
	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED)) {
			discovered_item_state_clr(e, DI_STATE_SELECTED);
			doSelect = 1;
		} else
		if (doSelect) {
			discovered_item_state_set(e, DI_STATE_SELECTED);
			break;
		}
	}
	pthread_mutex_unlock(&ctx->lock);

#if 0
	if (!doSelect)
		discovered_items_select_first(ctx);
#endif
}

void discovered_items_select_prev(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;
	struct discovered_item_s *p = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) && p) {
			discovered_item_state_clr(e, DI_STATE_SELECTED);
			discovered_item_state_set(p, DI_STATE_SELECTED);
			break;
		}
		p = e;
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_all(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_state_set(e, DI_STATE_SELECTED);
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_none(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_state_clr(e, DI_STATE_SELECTED);
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_record_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_PCAP_RECORDING) || discovered_item_state_get(e, DI_STATE_PCAP_RECORD_START)) {
			discovered_item_state_set(e, DI_STATE_PCAP_RECORD_STOP);
		} else {
			discovered_item_state_set(e, DI_STATE_PCAP_RECORD_START);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_record_abort(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_PCAP_RECORDING) || discovered_item_state_get(e, DI_STATE_PCAP_RECORD_START)) {
			discovered_item_state_set(e, DI_STATE_PCAP_RECORD_STOP);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_show_pids_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_SHOW_PIDS)) {
			discovered_item_state_clr(e, DI_STATE_SHOW_PIDS);
		} else {
			discovered_item_state_set(e, DI_STATE_SHOW_PIDS);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_show_tr101290_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_SHOW_TR101290)) {
			discovered_item_state_clr(e, DI_STATE_SHOW_TR101290);
		} else {
			discovered_item_state_set(e, DI_STATE_SHOW_TR101290);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_free(struct tool_context_s *ctx)
{
	struct discovered_item_s *di = NULL;

	pthread_mutex_lock(&ctx->lock);
        while (!xorg_list_is_empty(&ctx->list)) {
		di = xorg_list_first_entry(&ctx->list, struct discovered_item_s, list);
		xorg_list_del(&di->list);
		discovered_item_free(di);
	}
	pthread_mutex_unlock(&ctx->lock);
}

