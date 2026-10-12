#include "nic_monitor.h"

static struct scte35_pid_item_s *scte35_pid_find(struct discovered_item_s *di, uint16_t pid)
{
	struct scte35_pid_item_s *item = NULL;

	xorg_list_for_each_entry(item, &di->listSCTE35Pids, list) {
		if (item->pid == pid)
			return item;
	}

	return NULL;
}

static void scte35_pid_free(struct scte35_pid_item_s *item)
{
	if (item->sectionExtractor)
		ltntstools_sectionextractor_free(item->sectionExtractor);
	if (item->pesExtractor)
		ltntstools_pes_extractor_free(item->pesExtractor);
	free(item);
}

static void scte35_message_free(struct scte35_message_item_s *item)
{
	free(item->section);
	free(item->json);
	free(item);
}

static void *scte35_video_pes_cb(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct scte35_pid_item_s *item = userContext;

	item->lastVideoPTS = pes->PTS;
	ltn_pes_packet_free(pes);

	return NULL;
}

void scte35_monitor_prune(struct discovered_item_s *di, time_t now)
{
	struct scte35_message_item_s *item = NULL;
	struct scte35_message_item_s *next = NULL;
	time_t cutoff = now - SCTE35_HISTORY_SECONDS;

	xorg_list_for_each_entry_safe(item, next, &di->listSCTE35Messages, list) {
		if (item->receivedAt >= cutoff)
			continue;

		xorg_list_del(&item->list);
		scte35_message_free(item);
	}
}

void scte35_monitor_free(struct discovered_item_s *di)
{
	pthread_mutex_lock(&di->scte35Lock);

	while (!xorg_list_is_empty(&di->listSCTE35Pids)) {
		struct scte35_pid_item_s *item = xorg_list_first_entry(&di->listSCTE35Pids, struct scte35_pid_item_s, list);
		xorg_list_del(&item->list);
		scte35_pid_free(item);
	}

	while (!xorg_list_is_empty(&di->listSCTE35Messages)) {
		struct scte35_message_item_s *item = xorg_list_first_entry(&di->listSCTE35Messages, struct scte35_message_item_s, list);
		xorg_list_del(&item->list);
		scte35_message_free(item);
	}

	pthread_mutex_unlock(&di->scte35Lock);
	pthread_mutex_destroy(&di->scte35Lock);
}

static struct scte35_pid_item_s *scte35_pid_add(struct discovered_item_s *di, uint16_t pid)
{
	struct scte35_pid_item_s *item = scte35_pid_find(di, pid);
	if (item)
		return item;

	item = calloc(1, sizeof(*item));
	if (!item)
		return NULL;

	item->pid = pid;
	if (ltntstools_sectionextractor_alloc(&item->sectionExtractor, pid, SCTE35_TABLE_ID) < 0) {
		free(item);
		return NULL;
	}

	xorg_list_append(&item->list, &di->listSCTE35Pids);
	return item;
}

static void scte35_ensure_video_pes_extractor(struct scte35_pid_item_s *item)
{
	if (item->pesExtractor || item->videoPid == 0)
		return;

	if (ltntstools_pes_extractor_alloc(&item->pesExtractor, item->videoPid, 0xe0,
		(pes_extractor_callback)scte35_video_pes_cb, item, (1024 * 1024), (1024 * 1024)) == 0) {
		ltntstools_pes_extractor_set_skip_data(item->pesExtractor, 1);
	}
}

static void scte35_discover_pids(struct discovered_item_s *di, time_t now)
{
	struct ltntstools_pat_s *pat = NULL;

	if (di->lastSCTE35Discover == now)
		return;
	di->lastSCTE35Discover = now;

	if (!di->streamModel)
		return;
	if (ltntstools_streammodel_query_model(di->streamModel, &pat) != 0 || !pat)
		return;

	int e = 0;
	struct ltntstools_pmt_s *pmt = NULL;
	uint16_t *scte35pids = NULL;
	int scte35pid_count = 0;
	while (ltntstools_pat_enum_services_scte35(pat, &e, &pmt, &scte35pids, &scte35pid_count) == 0) {
		uint8_t estype = 0;
		uint16_t videopid = 0;
		ltntstools_pmt_query_video_pid(pmt, &videopid, &estype);

		for (int i = 0; i < scte35pid_count; i++) {
			struct scte35_pid_item_s *item = scte35_pid_add(di, scte35pids[i]);
			if (item) {
				item->videoPid = videopid;
				scte35_ensure_video_pes_extractor(item);
			}
		}

		free(scte35pids);
		scte35pids = NULL;
		scte35pid_count = 0;
	}

	ltntstools_pat_free(pat);
}

static void scte35_store_message(struct discovered_item_s *di, struct scte35_pid_item_s *pidItem,
	const uint8_t *section, size_t sectionLengthBytes, int crcValid, time_t now)
{
	struct scte35_message_item_s *msg = calloc(1, sizeof(*msg));
	if (!msg)
		return;

	msg->section = malloc(sectionLengthBytes);
	if (!msg->section) {
		free(msg);
		return;
	}

	memcpy(msg->section, section, sectionLengthBytes);
	msg->sectionLengthBytes = sectionLengthBytes;
	msg->receivedAt = now;
	msg->pid = pidItem->pid;
	msg->videoPid = pidItem->videoPid;
	msg->videoPTS = pidItem->lastVideoPTS;
	msg->crcValid = crcValid;
	msg->sequenceNumber = ++di->scte35MessageCount;
	pidItem->messageCount++;

	if (crcValid) {
		struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(section, sectionLengthBytes);
		if (s) {
			if (pidItem->lastVideoPTS)
				s->user_current_video_pts = pidItem->lastVideoPTS;

			char *json = NULL;
			uint16_t jsonByteCount = 0;
			if (scte35_create_json_message(s, &json, &jsonByteCount, 0) == 0 && json) {
				msg->json = json;
				msg->parseOk = 1;
			}
			scte35_splice_info_section_free(s);
		}
	}

	xorg_list_append(&msg->list, &di->listSCTE35Messages);
	scte35_monitor_prune(di, now);
}

void scte35_monitor_write(struct discovered_item_s *di, const uint8_t *pkts, uint32_t pktCount)
{
	if (!di || !pkts || pktCount == 0)
		return;
	if (di->payloadType != PAYLOAD_UDP_TS && di->payloadType != PAYLOAD_RTP_TS && di->payloadType != PAYLOAD_SRT_TS)
		return;

	time_t now = time(NULL);

	pthread_mutex_lock(&di->scte35Lock);
	scte35_discover_pids(di, now);

	struct scte35_pid_item_s *pidItem = NULL;
	xorg_list_for_each_entry(pidItem, &di->listSCTE35Pids, list) {
		int secomplete = 0;
		int crcValid = 0;

		if (pidItem->pesExtractor)
			ltntstools_pes_extractor_write(pidItem->pesExtractor, pkts, pktCount);
		if (!pidItem->sectionExtractor)
			continue;

		ltntstools_sectionextractor_write(pidItem->sectionExtractor, pkts, pktCount, &secomplete, &crcValid);
		if (!secomplete)
			continue;

		uint8_t section[4096];
		memset(section, 0, sizeof(section));
		int sectionLengthBytes = ltntstools_sectionextractor_query(pidItem->sectionExtractor, section, sizeof(section));
		if (sectionLengthBytes <= 0)
			continue;

		scte35_store_message(di, pidItem, section, sectionLengthBytes, crcValid, now);
	}

	scte35_monitor_prune(di, now);
	pthread_mutex_unlock(&di->scte35Lock);
}
