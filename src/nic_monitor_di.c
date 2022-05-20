
#include "nic_monitor.h"

uint16_t hash_index_cal_hash(uint32_t addr, uint16_t port)
{
	 /*
	  * AB.CD.EF.GH:IJKL
	  *
	  * Hash: FGHL
	  */
	return ((addr << 4) & 0xfff0) | (port & 0x000f);
}

static uint16_t _compute_stream_hash(struct iphdr *iphdr, struct udphdr *udphdr)
{
	/* Compute the destination hash for faster lookup */
#ifdef __APPLE__
	uint32_t dstaddr = ntohl(iphdr->ip_dst.s_addr);
#endif
#ifdef __linux__
	uint32_t dstaddr = ntohl(iphdr->daddr);
#endif
	uint16_t dstport = ntohs(udphdr->uh_dport);
	return hash_index_cal_hash(dstaddr, dstport);
}

static const char *payloadTypes[] = {
	"???",
	"UDP",
	"RTP",
	"STL",
	"UNK",
	"21V",
	"21A",
	"21D",
};

const char *payloadTypeDesc(enum payload_type_e pt)
{
	if (pt >= PAYLOAD_MAX)
		return payloadTypes[0];

	return payloadTypes[pt];
}

void discovered_item_free(struct discovered_item_s *di)
{
	nic_monitor_tr101290_free(di);

	if (di->h264_metadata_parser) {
		pthread_mutex_lock(&di->h264_metadataLock);
		h264_slice_counter_free(di->h264_metadata_parser);
		/* Intensional permanent. */
	}
	if (di->h264_slices) {
		pthread_mutex_lock(&di->h264_sliceLock);
		h264_slice_counter_free(di->h264_slices);
		/* Intensional permanent. */
	}
	if (di->pcapRecorder) {
		ltntstools_segmentwriter_free(di->pcapRecorder);
		di->pcapRecorder = NULL;
	}

	if (di->packetIntervals) {
		ltn_histogram_free(di->packetIntervals);
		di->packetIntervals = NULL;
	}

	throughput_hires_free(di->packetIntervalAverages);

	if (di->streamModel) {
		ltntstools_streammodel_free(di->streamModel);
		di->streamModel = NULL;
	}

	if (di->LTNLatencyProbe) {
		ltntstools_probe_ltnencoder_free(di->LTNLatencyProbe);
		di->LTNLatencyProbe = NULL;
	}
#if PROBE_REPORTER
	kafka_free(di);
#endif

	free(di);
}

struct discovered_item_s *discovered_item_alloc(struct tool_context_s *ctx, struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr)
{
	struct discovered_item_s *di = calloc(1, sizeof(*di));
	if (di) {
		di->ctx = ctx;

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
		di->dstport = ntohs(di->udphdr.uh_dport);

		di->iat_lwm_us = 50000000;
		di->iat_hwm_us = -1;
		di->iat_cur_us = 0;

		ltn_histogram_alloc_video_defaults(&di->packetIntervals, "IAT Intervals");

		throughput_hires_alloc(&di->packetIntervalAverages, 20000); /* Sized for 210mbps */

		ltntstools_pid_stats_reset(&di->stats);

		/* Stream Model */
		if (ltntstools_streammodel_alloc(&di->streamModel, di) < 0) {
			fprintf(stderr, "\nUnable to allocate streammodel object, it's safe to continue.\n\n");
		}

		/* LTN Latency Estimator Probe - we'll only use this if we detect the LTN encoder */
		if (ltntstools_probe_ltnencoder_alloc(&di->LTNLatencyProbe) < 0) {
			fprintf(stderr, "\nUnable to allocate ltn encoder latency probe, it's safe to continue.\n\n");
		}

		pthread_mutex_init(&di->h264_sliceLock, NULL);
#if 0
		/* Keeping this disabled for the time being. */
		di->h264_slices = h264_slice_counter_alloc(0x31); /* 0x2000 by default, count all slices across all video pids. */
#endif

		pthread_mutex_init(&di->h264_metadataLock, NULL);
#if 0
		if (ltntstools_h264_codec_metadata_alloc(&di->h264_metadata_parser, 0x31, 0xe0) < 0) {
			fprintf(stderr, "\nUnable to allocate h264 metadata parser, it's safe to continue.\n\n");
		}
#endif

		pthread_mutex_init(&di->h265_metadataLock, NULL);
#if 0
		if (ltntstools_h265_codec_metadata_alloc(&di->h265_metadata_parser, 0x31, 0xe0) < 0) {
			fprintf(stderr, "\nUnable to allocate h265 metadata parser, it's safe to continue.\n\n");
		}
#endif

#if 0
		if (nic_monitor_tr101290_alloc(di) < 0) {
			fprintf(stderr, "\nUnable to allocate tr101290 analyzer, it's safe to continue.\n\n");
		}
#endif

#if PROBE_REPORTER
#if 1
		if (kafka_initialize(di) < 0) {
			fprintf(stderr, "\nUnable to allocate kafka connector, it's safe to continue.\n\n");
		}
#endif
#endif

#if 0
		display_doc_initialize(&di->doc_scte35);
		display_doc_append(&di->doc_scte35, "first line");
		display_doc_append(&di->doc_scte35, "second line");
		display_doc_append(&di->doc_scte35, "3 line");
		display_doc_append(&di->doc_scte35, "4 line");
		display_doc_append(&di->doc_scte35, "5 line");
		display_doc_append(&di->doc_scte35, "6 line");
		display_doc_append(&di->doc_scte35, "7 line");
		display_doc_append(&di->doc_scte35, "8 line");
		display_doc_append(&di->doc_scte35, "9 line");
		display_doc_append(&di->doc_scte35, "10 line");
		display_doc_append(&di->doc_scte35, "11 line");
		display_doc_append(&di->doc_scte35, "12 line");
		display_doc_append(&di->doc_scte35, "13 line");
		display_doc_append(&di->doc_scte35, "14 line");
		display_doc_append(&di->doc_scte35, "15 line");
		display_doc_append(&di->doc_scte35, "16 line");
		display_doc_append(&di->doc_scte35, "17 line");
		display_doc_append(&di->doc_scte35, "18 line");
#endif
	}

	return di;
}

static int is_di_streaming(struct discovered_item_s *di, time_t now)
{
	if (di->lastUpdated + 5 < now)
		return 0;

	return 1;
}

static int is_di_duplicate(struct discovered_item_s *x, struct discovered_item_s *y)
{
#ifdef __linux__
	if (x->iphdr.saddr != y->iphdr.saddr)
		return 0;
	if (x->iphdr.daddr != y->iphdr.daddr)
		return 0;
	if (x->udphdr.uh_sport != y->udphdr.uh_sport)
		return 0;
	if (x->udphdr.uh_dport != y->udphdr.uh_dport)
		return 0;

#endif
#ifdef __APPLE__
	if (x->iphdr.ip_src.s_addr != y->iphdr.ip_src.s_addr)
		return 0;
	if (x->iphdr.ip_dst.s_addr != y->iphdr.ip_dst.s_addr)
		return 0;
	if (x->udphdr.uh_sport != y->udphdr.uh_sport)
		return 0;
	if (x->udphdr.uh_dport != y->udphdr.uh_dport)
		return 0;
#endif

	return 1;
}

static int is_di_dst_duplicate(struct discovered_item_s *x, struct discovered_item_s *y)
{
#ifdef __linux__
	uint64_t a = (uint64_t)ntohl(x->iphdr.daddr) << 16;
	a |= (x->udphdr.uh_dport);

	uint64_t b = (uint64_t)ntohl(y->iphdr.daddr) << 16;
	b |= (y->udphdr.uh_dport);
#endif
#ifdef __APPLE__
	uint64_t a = (uint64_t)ntohl(x->iphdr.ip_dst.s_addr) << 16;
	a |= (x->udphdr.uh_dport);

	uint64_t b = (uint64_t)ntohl(y->iphdr.ip_dst.s_addr) << 16;
	b |= (y->udphdr.uh_dport);
#endif

	if (a == b)
		return 1;

	return 0;
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
#ifdef __APPLE__
		uint64_t a = (uint64_t)ntohl(e->iphdr.ip_dst.s_addr) << 16;
		a |= (e->udphdr.uh_dport);

		uint64_t b = (uint64_t)ntohl(di->iphdr.ip_dst.s_addr) << 16;
		b |= (di->udphdr.uh_dport);
#endif
		if (a < b)
			continue;

		/* If we find a duplicate UDP destination address:port, mark the object a dup
		 * for later wanring/reporting purposes.
		 */
		if (a == b) {
			discovered_item_state_set(di, DI_STATE_DST_DUPLICATE);
			discovered_item_state_set(e, DI_STATE_DST_DUPLICATE);
		}
		xorg_list_add(&di->list, e->list.prev);
		return;
	}

	xorg_list_append(&di->list, &ctx->list);
}

/* Before August 2021, di object lookup takes an excessive amount of CPU with large numbers of streams.
   To investigate this, in a test case, were I had 99 streams all going to ports
   4001-4099, and I put a static fixed array in play with a fast direct lookup,
   I saved 50% CPU in the pcap thread and 75% CPU in the stats thread.
   So, optimization is worthwhile but a more flexible approach was needed.

   Instead:
   Build a hashing function that makes our streams 'fairly' unique,
   with room for some overflow hashes.
   Put this into a static array of 65536 addresses, with pointers to a new
   struct {
      // Contains ideally the only DI object associated with the hash
      // But could contain multiple di objects matching this hash
      struct discovered_item_s *array[];
      int arrlen;
   }
   when asked to search for a di object.
   1. compute the hash as a uint16_t hash = X.
   2. check globalhashtable[ hash ], if not set, create a new object general object.
   3.  if set, look manually at all the entries in hash entry array, looking for the specific record.
       if not found, create a new object.
       if found, optimization achieved.

  The result of this optimzation, in the following configuration:
   DC60 older hardware with a 10Gb card, playing out 99 x 20Mbps streams
   With a total output capacity of 2Gb, running tstools on the same
   system.

   Performance:     NoCache   Cache
      pcap-thread       65%     33%
     stats-thread       35%      5%
*/

struct discovered_item_s *discovered_item_findcreate(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr)
{
	struct discovered_item_s *found = NULL;

	/* Compute the src/dst ip/udp address/ports hash for faster lookup */
	uint16_t hash = _compute_stream_hash(iphdr, udphdr);

	if (ctx->verbose > 2) {
		char *str = network_stream_ascii(iphdr, udphdr);
		printf("cache srch on %s\n", str);
		free(str);
		if (ctx->verbose > 3) {
			hash_index_print(ctx->hashIndex, hash);
		}
	}

	pthread_mutex_lock(&ctx->lock);

	/* With the hash, lookup the di objects in the cachelist. */
	if (hash_index_get_count(ctx->hashIndex, hash) >= 1) {
		/* One or more items in the cache for the same hash,
		 * we have to enum and locate our exact item.
		 * The hash has reasonable selectivity, but overflows can occur.
		 */
		struct discovered_item_s *item = NULL;
		int enumerator = 0;
		int ret = 0;
		while (ret == 0) {
			ret = hash_index_get_enum(ctx->hashIndex, hash, &enumerator, (void **)&item);
			if (ret == 0 && item) {
				/* Do a 100% perfect match on the ip and udp headers */
				if (network_addr_compare(iphdr, udphdr, &item->iphdr, &item->udphdr) == 1) {
					/* Found the perfect match in the cache */
					found = item;
					break;
				}
			}
		}
	}

	if (!found) {
		ctx->cacheMiss++;

		if (ctx->verbose > 3) {
			char *str = network_stream_ascii(iphdr, udphdr);
			printf("cache miss on %s\n", str);
			free(str);
		}

	} else {
		ctx->cacheHit++;

		if (ctx->verbose > 3) {
			char *str = network_stream_ascii(iphdr, udphdr);
			printf("cache  hit on %s\n", str);
			free(str);
		}

	}
	ctx->cacheHitRatio = 100.0 - (((double)ctx->cacheMiss / (double)ctx->cacheHit) * 100.0);

#if 0
	/* A refactored older mechanism, look through the entire array
	 * which gets super expensive as the number of streams increases.
	 */
	if (!found) {
                struct discovered_item_s *e = NULL;
		/* Enumerate the di array for each input packet.
		 * It works well for 1-2 dozen streams, but doesn't scale well beyond this.
		 * We never really want to do this, this can go away.
		 */
		xorg_list_for_each_entry(e, &ctx->list, list) {
			if (network_addr_compare(iphdr, udphdr, &e->iphdr, &e->udphdr) == 1) {
				found = e;
				break;
			}
		}
	}
#endif

	if (!found) {
		found = discovered_item_alloc(ctx, ethhdr, iphdr, udphdr);
		if (found) {
			discovered_item_insert(ctx, found);
			hash_index_set(ctx->hashIndex, hash, found);

			if (ctx->automaticallyRecordStreams) {
				discovered_item_state_set(found, DI_STATE_PCAP_RECORD_START);
			}
#if PROBE_REPORTER
			if (ctx->automaticallyJSONProbeStreams) {
				discovered_item_state_set(found, DI_STATE_JSON_PROBE_ACTIVE);
			}
#endif
		}
	}
	pthread_mutex_unlock(&ctx->lock);

	return found;
}

#if PROBE_REPORTER

/* See prometheus integration:
 *  https://github.com/prometheus-community/json_exporter
 */

/* Collect a json summary per stream, serialize the findout string output
 * into a content and puth this on a thread queue for something else to push to a remote server.
 * We don't want a bogus http push to block processing, so a backlog could build up,
 * be mindful of this.
 */
void discovered_item_json_summary(struct tool_context_s *ctx, struct discovered_item_s *di)
{
	/* TODO, looks for leaks and make sure we're releaseing objects here. */

	/* Feed */
	json_object *feed = json_object_new_object();

	char ts[64];
#if 0
	libltntstools_getTimestamp(&ts[0], sizeof(ts), NULL);
#else
	time_t now = time(NULL);
	strftime(ts, sizeof(ts), "%F %T.000", localtime(&now));
#endif

	json_object *fts = json_object_new_string(ts);

	char hostname[64];
	gethostname(&hostname[0], sizeof(hostname));
	json_object *fhost = json_object_new_string(hostname);

	json_object *fsrc = json_object_new_string(di->srcaddr);
	json_object *fdst = json_object_new_string(di->dstaddr);
	json_object *fmbps = json_object_new_double(ltntstools_pid_stats_stream_get_mbps(&di->stats));
	json_object *ftype = json_object_new_string(payloadTypeDesc(di->payloadType));
	json_object *nic = json_object_new_string(ctx->ifname);
	json_object *fccerr = json_object_new_int64(di->stats.ccErrors);
	json_object *fpkts = json_object_new_int64(di->stats.packetCount);
	json_object *fpsdrop = json_object_new_int64(ctx->pcap_stats.ps_drop);
	json_object *fifdrop = json_object_new_int64(ctx->pcap_stats.ps_ifdrop);

	json_object_object_add(feed, "host", fhost);
	json_object_object_add(feed, "timestamp", fts);
	json_object_object_add(feed, "type", ftype);
	json_object_object_add(feed, "src", fsrc);
	json_object_object_add(feed, "dst", fdst);

	double la[3] = { 0.0, 0.0, 0.0 };
	if (getloadavg(&la[0], 3) == 3) {
		json_object *la1 = json_object_new_double(la[0]);
		json_object *la5 = json_object_new_double(la[1]);
		json_object *la15 = json_object_new_double(la[2]);

		json_object_object_add(feed, "la1", la1);
		json_object_object_add(feed, "la5", la5);
		json_object_object_add(feed, "la15", la15);
	}

	/* IATs - Min/MAX?AVG stats for the last 1 second. */
	int64_t iat_min, iat_max, iat_avg;
	throughput_hires_minmaxavg_i64(di->packetIntervalAverages, 0, NULL, NULL, &iat_min, &iat_max, &iat_avg);
	throughput_hires_expire(di->packetIntervalAverages, NULL); /* Expire anything older than 2 seconds. */

	json_object *iat1_min = json_object_new_int64(iat_min);
	json_object *iat1_max = json_object_new_int64(iat_max);
	json_object *iat1_avg = json_object_new_int64(iat_avg);

	/* Feed statistics */
	json_object *feedstats = json_object_new_object();
	json_object_object_add(feedstats, "mbps", fmbps);
	json_object_object_add(feedstats, "ccerrors", fccerr);
	json_object_object_add(feedstats, "packetcount", fpkts);
	json_object_object_add(feedstats, "nic", nic);
	json_object_object_add(feedstats, "pcap_ifdrop", fifdrop);
	json_object_object_add(feedstats, "pcap_psdrop", fpsdrop);
	json_object_object_add(feedstats, "iat1_min", iat1_min);
	json_object_object_add(feedstats, "iat1_max", iat1_max);
	json_object_object_add(feedstats, "iat1_avg", iat1_avg);
	json_object_object_add(feed, "stats", feedstats);

	/* Services */
	json_object *services = json_object_new_array();

	struct ltntstools_pat_s *m = NULL;
	if (ltntstools_streammodel_query_model(di->streamModel, &m) == 0) {
		for (int p = 0; p < m->program_count; p++) {
			if (m->programs[p].program_number == 0)
				continue; /* Skip the NIT pid */

			json_object *item = json_object_new_object();
			json_object *nr = json_object_new_int64(m->programs[p].program_number);
			
			char pidstr[64];
			sprintf(pidstr, "0x%04x", m->programs[p].program_map_PID);
			json_object *pmtpid = json_object_new_string(pidstr);

			sprintf(pidstr, "0x%04x", m->programs[p].pmt.PCR_PID);
			json_object *pcrpid = json_object_new_string(pidstr);

			json_object *escount = json_object_new_int64(m->programs[p].pmt.stream_count);
								
			json_object_object_add(item, "program", nr);
			json_object_object_add(item, "pmtpid", pmtpid);
			json_object_object_add(item, "pcrpid", pcrpid);
			json_object_object_add(item, "escount", escount);

			json_object *streams = json_object_new_array();

			for (int s = 0; s < m->programs[p].pmt.stream_count; s++) {
				const char *d = ltntstools_GetESPayloadTypeDescription(m->programs[p].pmt.streams[s].stream_type);

				json_object *item = json_object_new_object();

				char pidstr[64];
				sprintf(pidstr, "0x%04x", m->programs[p].pmt.streams[s].elementary_PID);
				json_object *espid = json_object_new_string(pidstr);

				sprintf(pidstr, "0x%02x", m->programs[p].pmt.streams[s].stream_type);
				json_object *estype = json_object_new_string(pidstr);
				json_object *esdesc = json_object_new_string(d);

				json_object_object_add(item, "pid", espid);
				json_object_object_add(item, "type", estype);
				json_object_object_add(item, "desc", esdesc);

				json_object_array_add(streams, item);

			}
			json_object_object_add(item, "streams", streams);
			json_object_array_add(services, item);

		}
		json_object_object_add(feed, "services", services);
	}
	ltntstools_pat_free(m);
	m = NULL;

	/* Pids */
	json_object *array = json_object_new_array();

	for (int i = 0; i < MAX_PID; i++) {
		if (di->stats.pids[i].enabled == 0)
			continue;

		char pidstr[64];
		sprintf(pidstr, "0x%04x", i);
		json_object *pid = json_object_new_string(pidstr);
		json_object *pc = json_object_new_int64(di->stats.pids[i].packetCount);
		json_object *cc = json_object_new_int64(di->stats.pids[i].ccErrors);
		json_object *mbps = json_object_new_double(ltntstools_pid_stats_pid_get_mbps(&di->stats, i));

		json_object *item = json_object_new_object();
		json_object_object_add(item, "pid", pid);
		json_object_object_add(item, "packetcount", pc);
		json_object_object_add(item, "ccerrors", cc);
		json_object_object_add(item, "mbps", mbps);
		json_object_array_add(array, item);
	}

	json_object_object_add(feed, "pids", array);

#if 1
	printf("%s\n",
		json_object_to_json_string_ext(feed,
#if 0
		JSON_C_TO_STRING_PRETTY
#else
		JSON_C_TO_STRING_PLAIN
#endif
		));
#endif

#if 0
	/* Push the final output to a queue, it will be serviced for output later.
	 * Max size of allowable message is 64k
	 */
	struct json_item_s *qi = json_item_alloc(ctx, 65536);
	if (qi) {
		/* double crlf, keep the cheap base64encoder happy. */
		sprintf((char *)qi->buf, "%s\n\n", json_object_to_json_string_ext(feed, JSON_C_TO_STRING_PRETTY));
		qi->lengthBytes = strlen((char *)qi->buf);	
		json_queue_push(ctx, qi);
	}

	struct kafka_item_s *ki = kafka_item_alloc(di, 65536);
	if (ki) {
		/* double crlf, keep the cheap base64encoder happy. */
		sprintf((char *)ki->buf, "%s\n\n", json_object_to_json_string_ext(feed, JSON_C_TO_STRING_PRETTY));
		ki->lengthBytes = strlen((char *)ki->buf);	
		kafka_queue_push(di, ki);
	}
#endif

	json_object_put(feed);

}

/* Write all the stream statistics to a remote server.
 * use a seperate background thread to make this happen,
 * so we don't block the stats thread in the event of
 * a network / remote server outage.
 */
void discovered_items_json_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_JSON_PROBE_ACTIVE) == 0)
			continue;
		discovered_item_json_summary(ctx, e);
	}
	pthread_mutex_unlock(&ctx->lock);
}

/* Write all the stream statistics to a remote server.
 * use a seperate background thread to make this happen,
 * so we don't block the stats thread in the event of
 * a network / remote server outage.
 */
void discovered_items_kafka_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_JSON_PROBE_ACTIVE) == 0)
			continue;
		kafka_queue_process(e);
	}
	pthread_mutex_unlock(&ctx->lock);
}
#endif

/* Perform any periodic tasks intermittently on the list of di's.
 * Such as pruning old/stale di objects.
 * Housekeeping runs every 15 seconds.
 */
void discovered_items_housekeeping(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;
	struct discovered_item_s *f = NULL;

	/* Housekeeping runs only periodically. */
	time_t now = time(NULL);
	if (ctx->lastListHousekeeping + 6 > now) {
		return;
	}
	ctx->lastListHousekeeping = now;

	/* 1. Hide any objects that are stale. */
	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {

		/* We aren't interested in non-duplicates */
		if (discovered_item_state_get(e, DI_STATE_DST_DUPLICATE) == 0)
			continue;

		/* Process a duplicate object, we don't know what we're a duplicate of,
		 * so lets examine state and decide if we need to expire this di.
		 * di->lastUpdated is time_t, and should represent 'now'. When this falls
		 * behind significantly, because of no updates to the object, no data
		 * from the network, take action to hide/remove the object from reports.
		 */
		if (is_di_streaming(e, now)) {
			discovered_item_state_clr(e, DI_STATE_HIDDEN);
		} else {
			/* if this is a dup, and it's not already hidden, hide it. */
			discovered_item_state_set(e, DI_STATE_HIDDEN);
		}

	}
	pthread_mutex_unlock(&ctx->lock);

	/* 2. update the duplicate status for each object, based on hidden and usage state. */
	pthread_mutex_lock(&ctx->lock);
	e = NULL;
	xorg_list_for_each_entry(e, &ctx->list, list) {

		/* find all duplicates of this object. */
		int numberActiveDuplicates = 0;
		int numberHiddenDuplicates = 0;
		f = NULL;
		xorg_list_for_each_entry(f, &ctx->list, list) {
			if (is_di_duplicate(e, f))
				continue; /* Discard matching against outrself */

			if (is_di_dst_duplicate(e, f)) {
				numberHiddenDuplicates++;
				if (is_di_streaming(e, now) && is_di_streaming(f, now)) {
					numberActiveDuplicates++;					
					discovered_item_state_clr(f, DI_STATE_HIDDEN);
					discovered_item_state_set(f, DI_STATE_DST_DUPLICATE);
				}
				if (is_di_streaming(e, now) && is_di_streaming(f, now) == 0) {
					e->hasHiddenDuplicates = 1;
				}
			}

		}

		if (is_di_streaming(e, now)) {
			if (numberActiveDuplicates) {
				discovered_item_state_set(e, DI_STATE_DST_DUPLICATE);
			} else {
				discovered_item_state_clr(e, DI_STATE_DST_DUPLICATE);
			}
		}

	}
	pthread_mutex_unlock(&ctx->lock);

}

void discovered_item_fd_per_pid_report(struct tool_context_s *ctx, struct discovered_item_s *di, int fd)
{
	char stream[128];
	sprintf(stream, "%s", di->srcaddr);
	sprintf(stream + strlen(stream), " -> %s", di->dstaddr);

	dprintf(fd, "   PID   PID     PacketCount     CCErrors    TEIErrors @ %6.2f : %s (%s)\n",
		ltntstools_pid_stats_stream_get_mbps(&di->stats), stream,
		payloadTypeDesc(di->payloadType));
	dprintf(fd, "<---------------------------  ----------- ------------ ---Mb/ps------------------------------------------------>\n");
	for (int i = 0; i < MAX_PID; i++) {
		if (di->stats.pids[i].enabled) {
			dprintf(fd, "0x%04x (%4d) %14" PRIu64 " %12" PRIu64 "%s%12" PRIu64 "   %6.2f\n", i, i,
				di->stats.pids[i].packetCount,
				di->stats.pids[i].ccErrors,
				di->stats.pids[i].ccErrors != di->statsToFileSummary.pids[i].ccErrors ? "!" : " ",
				di->stats.pids[i].teiErrors,
				ltntstools_pid_stats_pid_get_mbps(&di->stats, i));
		}
	}
	ltn_histogram_interval_print(fd, di->packetIntervals, 0);
	dprintf(fd, "\n");
}

void discovered_item_fd_per_h264_slice_report(struct tool_context_s *ctx, struct discovered_item_s *di, int fd)
{
	int slicesEnabled = 0;
	uint16_t pid;
	struct h264_slice_counter_results_s slices;

	pthread_mutex_lock(&di->h264_sliceLock);
	if (di->h264_slices) {
		slicesEnabled = 1;
		h264_slice_counter_query(di->h264_slices, &slices);
		pid = h264_slice_counter_get_pid(di->h264_slices);
	}
	pthread_mutex_unlock(&di->h264_sliceLock);

	if (slicesEnabled) {
		dprintf(fd, "H264 frame types/counts for PID 0x%04x - I: %'" PRIu64 " B: %'" PRIu64 " P: %'" PRIu64 " : %s...\n",
			pid,
			slices.i, slices.b, slices.p,
			slices.sliceHistory);
		if (pid == 0x2000) {
			dprintf(fd, "-> Summary represents all pids in the MPTS (PID 0x2000)\n");
		}
	}

	dprintf(fd, "\n");
}

void discovered_items_console_summary(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_fd_per_pid_report(ctx, e, STDOUT_FILENO);
		discovered_item_fd_per_h264_slice_report(ctx, e, STDOUT_FILENO);
#if PROBE_REPORTER
		discovered_item_json_summary(ctx, e);
#endif
	}
	pthread_mutex_unlock(&ctx->lock);
}

/* For a given item, open a detailed stats file on disk, append the current stats, close it. */
void discovered_item_detailed_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di, int write_banner)
{
	if (di->detailed_filename[0] == 0) {
		if (ctx->detailed_file_prefix) {
			if (strlen(ctx->detailed_file_prefix) == 1 && ctx->detailed_file_prefix[0] == '.') {
				sprintf(di->detailed_filename, "%s/", ctx->detailed_file_prefix);
			} else {
				sprintf(di->detailed_filename, "%s", ctx->detailed_file_prefix);
			}
		}

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

	if (write_banner) {
		sprintf(line, "@Report begins %s\n", ts);
		write(fd, line, strlen(line));
	}

	uint32_t bps = 0;
	double mbps = 0;
	if ((di->payloadType == PAYLOAD_UDP_TS) || (di->payloadType == PAYLOAD_RTP_TS)) {
		mbps = ltntstools_pid_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_pid_stats_stream_get_bps(&di->stats);
	} else
	if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
		mbps = ltntstools_ctp_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_ctp_stats_stream_get_bps(&di->stats);
	} else
	if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
		mbps = ltntstools_ctp_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_ctp_stats_stream_get_bps(&di->stats);
	} else
	if (di->payloadType == PAYLOAD_A324_CTP) {
		mbps = ltntstools_ctp_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_ctp_stats_stream_get_bps(&di->stats);
	} else {
		mbps = ltntstools_bytestream_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_bytestream_stats_stream_get_bps(&di->stats);
	}
	sprintf(line, "time=%s,nic=%s,bps=%d,mbps=%.2f,tspacketcount=%" PRIu64 ",ccerrors=%" PRIu64 "%s,src=%s,dst=%s,dropped=%d/%d,iat=%d%s\n",
		ts,
		ctx->ifname,
		bps,
		mbps,
		di->stats.packetCount,
		di->stats.ccErrors,
		di->stats.ccErrors != di->statsToFileDetailed.ccErrors ? "!" : "",
		di->srcaddr,
		di->dstaddr,
		ctx->pcap_stats.ps_drop,
		ctx->pcap_stats.ps_ifdrop,
		di->iat_hwm_us / 1000,
		di->iat_hwm_us / 1000 > ctx->iatMax ? "!" : "");

	write(fd, line, strlen(line));

	/* Write out the entire PID state. */
	discovered_item_fd_per_pid_report(ctx, di, fd);

	close(fd);
}

/* For a given item, open a stats file on disk, append the current stats, close it. */
void discovered_item_file_summary(struct tool_context_s *ctx, struct discovered_item_s *di, int write_banner)
{
	if (di->filename[0] == 0) {
		if (ctx->file_prefix) {
			if (strlen(ctx->file_prefix) == 1 && ctx->file_prefix[0] == '.') {
				sprintf(di->filename, "%s/", ctx->file_prefix);
			} else {
				sprintf(di->filename, "%s", ctx->file_prefix);
			}
		}

		sprintf(di->filename + strlen(di->filename), "%s", di->dstaddr);
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

	if (write_banner) {
		sprintf(line, "@Report begins %s\n", ts);
		write(fd, line, strlen(line));
	}

	uint32_t bps = 0;
	double mbps = 0;
	if ((di->payloadType == PAYLOAD_UDP_TS) || (di->payloadType == PAYLOAD_RTP_TS)) {
		mbps = ltntstools_pid_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_pid_stats_stream_get_bps(&di->stats);
	} else
	if (di->payloadType == PAYLOAD_A324_CTP) {
		mbps = ltntstools_ctp_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_ctp_stats_stream_get_bps(&di->stats);
	} else
	if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
		mbps = ltntstools_ctp_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_ctp_stats_stream_get_bps(&di->stats);
	} else
	if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
		mbps = ltntstools_ctp_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_ctp_stats_stream_get_bps(&di->stats);
	} else {
		mbps = ltntstools_bytestream_stats_stream_get_mbps(&di->stats);
		bps = ltntstools_bytestream_stats_stream_get_bps(&di->stats);
	}
	sprintf(line, "time=%s,nic=%s,bps=%d,mbps=%.2f,tspacketcount=%" PRIu64 ",ccerrors=%" PRIu64 "%s,src=%s,dst=%s,dropped=%d/%d,iat=%d%s\n",
		ts,
		ctx->ifname,
		bps,
		mbps,
		di->stats.packetCount,
		di->stats.ccErrors,
		di->stats.ccErrors != di->statsToFileSummary.ccErrors ? "!" : "",
		di->srcaddr,
		di->dstaddr,
		ctx->pcap_stats.ps_drop,
		ctx->pcap_stats.ps_ifdrop,
		di->iat_hwm_us / 1000,
		di->iat_hwm_us / 1000 > ctx->iatMax ? "!" : "");
	write(fd, line, strlen(line));

	close(fd);
}

/* Create a file with a one line per second summary of overall stream stats. */
void discovered_items_file_summary(struct tool_context_s *ctx, int write_banner)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {

		if (discovered_item_state_get(e, DI_STATE_HIDDEN))
			continue;

		discovered_item_file_summary(ctx, e, write_banner);

		/* Implied memcpy of struct */
		/* Cache the current stats. When we prepare
		 * file records, of the CC counts have changed, we
		 * do something significant in the file records.
		 */
		e->statsToFileSummary = e->stats;
	}
	pthread_mutex_unlock(&ctx->lock);
}

/* Create a file with multiple line per second summary, overall stream stats plus detailed PID/Histogram stats */
void discovered_items_file_detailed(struct tool_context_s *ctx, int write_banner)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {

		if (discovered_item_state_get(e, DI_STATE_HIDDEN))
			continue;
			
		discovered_item_detailed_file_summary(ctx, e, write_banner);

		/* Implied memcpy of struct */
		/* Cache the current stats. When we prepare
		 * file records, of the CC counts have changed, we
		 * do something significant in the file records.
		 */
		e->statsToFileDetailed = e->stats;
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
		ltn_histogram_reset(e->packetIntervals);

		pthread_mutex_lock(&e->h264_sliceLock);
		if (e->h264_slices) {
			h264_slice_counter_reset(e->h264_slices);
		}
		pthread_mutex_unlock(&e->h264_sliceLock);

		nic_monitor_tr101290_reset(e);

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
		if (discovered_item_state_get(e, DI_STATE_HIDDEN))
			continue;
		if (discovered_item_state_get(e, DI_STATE_SELECTED)) {

			/* Only clear the current entry, if it's NOT the last entry in the list */
			if (e->list.next != &ctx->list)
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
		if (discovered_item_state_get(e, DI_STATE_HIDDEN))
			continue;
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

void discovered_items_abort(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_PCAP_RECORDING) || discovered_item_state_get(e, DI_STATE_PCAP_RECORD_START)) {
			discovered_item_state_set(e, DI_STATE_PCAP_RECORD_STOP);
		}
		if (discovered_item_state_get(e, DI_STATE_STREAM_FORWARDING) || discovered_item_state_get(e, DI_STATE_STREAM_FORWARD_START)) {
			discovered_item_state_set(e, DI_STATE_STREAM_FORWARD_STOP);
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

void discovered_items_select_show_iats_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_SHOW_IAT_HISTOGRAM)) {
			discovered_item_state_clr(e, DI_STATE_SHOW_IAT_HISTOGRAM);
		} else {
			discovered_item_state_set(e, DI_STATE_SHOW_IAT_HISTOGRAM);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_hide(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		/* No hiding if recording */
		if (discovered_item_state_get(e, DI_STATE_PCAP_RECORDING))
			continue;

		discovered_item_state_set(e, DI_STATE_HIDDEN);
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_unhide_all(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		discovered_item_state_clr(e, DI_STATE_HIDDEN);
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

void discovered_items_select_show_streammodel_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_SHOW_STREAMMODEL)) {
			discovered_item_state_clr(e, DI_STATE_SHOW_STREAMMODEL);
		} else {
			discovered_item_state_set(e, DI_STATE_SHOW_STREAMMODEL);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_show_processes_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_SHOW_PROCESSES)) {
			discovered_item_state_clr(e, DI_STATE_SHOW_PROCESSES);
		} else {
			discovered_item_state_set(e, DI_STATE_SHOW_PROCESSES);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_forward_toggle(struct tool_context_s *ctx, int slotNr)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_STREAM_FORWARDING) || discovered_item_state_get(e, DI_STATE_STREAM_FORWARD_START)) {
			discovered_item_state_set(e, DI_STATE_STREAM_FORWARD_STOP);
			e->forwardSlotNr = 0;
		} else {
			e->forwardSlotNr = slotNr;
			discovered_item_state_set(e, DI_STATE_STREAM_FORWARD_START);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

#if PROBE_REPORTER
void discovered_items_select_json_probe_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_JSON_PROBE_ACTIVE)) {
			discovered_item_state_clr(e, DI_STATE_JSON_PROBE_ACTIVE);
		} else {
			discovered_item_state_set(e, DI_STATE_JSON_PROBE_ACTIVE);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}
#endif

void discovered_items_select_scte35_toggle(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		if (discovered_item_state_get(e, DI_STATE_SHOW_SCTE35)) {
			discovered_item_state_clr(e, DI_STATE_SHOW_SCTE35);
		} else {
			discovered_item_state_set(e, DI_STATE_SHOW_SCTE35);
		}
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_scte35_pageup(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		display_doc_page_up(&e->doc_scte35);
	}
	pthread_mutex_unlock(&ctx->lock);
}

void discovered_items_select_scte35_pagedown(struct tool_context_s *ctx)
{
	struct discovered_item_s *e = NULL;

	pthread_mutex_lock(&ctx->lock);
	xorg_list_for_each_entry(e, &ctx->list, list) {
		if (discovered_item_state_get(e, DI_STATE_SELECTED) == 0)
			continue;

		display_doc_page_down(&e->doc_scte35);
	}
	pthread_mutex_unlock(&ctx->lock);
}

void display_doc_initialize(struct display_doc_s *doc)
{
	memset(doc, 0, sizeof(*doc));
	doc->displayLineFrom = 0;
	doc->pageSize = 0;
	doc->maxPageSize = 15;
}

int display_doc_append(struct display_doc_s *doc, const char *line)
{
	doc->lines = realloc(doc->lines, (doc->lineCount + 1) * sizeof(uint8_t *));
	if (!doc->lines)
		return -1;

	int slen = strlen(line);

	uint8_t *ptr = calloc(1, slen);
	if (!ptr)
		return -1;

	memcpy(ptr, line, slen);
	doc->lines[ doc->lineCount ] = ptr;

	doc->lineCount++;

	if (doc->lineCount < doc->maxPageSize)
		doc->pageSize = doc->lineCount;

	return doc->lineCount;
}

void display_doc_page_up(struct display_doc_s *doc)
{
	doc->displayLineFrom -= doc->pageSize;
	if (doc->displayLineFrom < 0)
		doc->displayLineFrom = 0;

	return;
}

void display_doc_page_down(struct display_doc_s *doc)
{
	doc->displayLineFrom += doc->pageSize;
	if (doc->displayLineFrom + doc->pageSize >= doc->lineCount)
		doc->displayLineFrom = doc->lineCount - doc->pageSize;
		
	return;
}

void display_doc_render(struct display_doc_s *doc, int row, int col)
{
	int l = 0;

	mvprintw(row + l, 64, "%d lines", doc->lineCount);

	for (int i = doc->displayLineFrom; i < (doc->displayLineFrom + doc->pageSize); i++) {
		if (i >= doc->lineCount)
			break;

		uint8_t *ptr = doc->lines[i];
		mvprintw(row + l, col, "xxx %s", ptr);
		l++;
	}
}
