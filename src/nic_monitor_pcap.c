#include "nic_monitor.h"

#define QUEUE_MIN (8 * 1024)

/* Initialize the queue to N items */
int pcap_queue_initialize(struct tool_context_s *ctx)
{
	pthread_mutex_lock(&ctx->lockpcap);

	for (int i = 0; i < QUEUE_MIN; i++) {
		struct pcap_item_s *item = malloc(sizeof(*item));
		if (item) {
			item->h = malloc(sizeof(struct pcap_pkthdr));
			item->pkt = malloc(1700);
			memset(item->pkt, 0xcd, 1700);
			xorg_list_append(&item->list, &ctx->listpcapFree);
			ctx->listpcapFreeDepth++;
		}
	}

	ctx->hashIndex = hash_index_alloc();

	pthread_mutex_unlock(&ctx->lockpcap);
	return 0;
}

void pcap_queue_free(struct tool_context_s *ctx)
{
	/* walk all queues and free and allocations */
	pthread_mutex_lock(&ctx->lockpcap);
	while (!xorg_list_is_empty(&ctx->listpcapFree)) {
		struct pcap_item_s *item = xorg_list_first_entry(&ctx->listpcapFree, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapFreeDepth--;
		free(item->h);
		free(item->pkt);
		free(item);
	}
	while (!xorg_list_is_empty(&ctx->listpcapUsed)) {
		struct pcap_item_s *item = xorg_list_first_entry(&ctx->listpcapUsed, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapUsedDepth--;
		free(item->h);
		free(item->pkt);
		free(item);
	}
	hash_index_free(ctx->hashIndex);
	pthread_mutex_unlock(&ctx->lockpcap);
}

int pcap_queue_push(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt)
{
	struct pcap_item_s *item = NULL;

	/* Either take a free item off the list or alloc a new item. */
	/* We're 100% free to hold the lockpcap mutex for as long as we want
	 * we're running on the most important thread in the design,
	 * any other thread who wants access to the listpcap* lists via
	 * this lock, will hold the lock for the purposes of moving
	 * list items into a temporary list.
	 */
	int ret = -1;

	pthread_mutex_lock(&ctx->lockpcap);

	do {
		if (xorg_list_is_empty(&ctx->listpcapFree)) {
			ctx->pcap_free_miss++;
			item = malloc(sizeof(*item));
			if (!item) {
				ctx->pcap_malloc_miss++;
				break;
			}

			item->h = malloc(sizeof(*h));
			if (!item->h) {
				ctx->pcap_malloc_miss++;
				free(item);
				break;
			}
			item->pkt = malloc(h->len);
			if (!item->pkt) {
				ctx->pcap_malloc_miss++;
				free(item->h);
				free(item);
				break;
			}
		} else {
			item = xorg_list_first_entry(&ctx->listpcapFree, struct pcap_item_s, list);
			xorg_list_del(&item->list);
			ctx->listpcapFreeDepth--;

			if (item->h->len < h->len)
				item->pkt = realloc(item->pkt, h->len);
		}

		memcpy(item->h, h, sizeof(*h));
		memcpy(item->pkt, pkt, h->len);
		xorg_list_append(&item->list, &ctx->listpcapUsed);
		ctx->listpcapUsedDepth++;

		/* Receiving thread isn't sitting on a semaphore, no point
		 * bradcasting a signal.
		 */

		ret = 0;

	} while (0);

	pthread_mutex_unlock(&ctx->lockpcap);

	return ret;
}

static enum payload_type_e determinePayloadType(struct discovered_item_s *di, const unsigned char *buf, int lengthBytes)
{
#if 0
printf("%d : ", lengthBytes);
for (int i = 0; i < 16; i++)
	printf("%02x ", *(buf + i));
printf("\n");
#endif
	const unsigned char *ptr = buf;

	if (lengthBytes % 188 == 0) {
		/* Perfect multiple for transport packets */
		int len = lengthBytes;
		int offset = 0;
		if ((len >= (188 * 3)) && (ptr[offset + (188 * 0)] == 0x47) && (ptr[offset + (188 * 1)] == 0x47) && (ptr[offset + (188 * 2)] == 0x47)) {
			return PAYLOAD_UDP_TS; /* After 3 sync bytes */
		}
		if ((len >= (188 * 2)) && (ptr[offset + (188 * 0)] == 0x47) && (ptr[offset + (188 * 1)] == 0x47)) {
			return PAYLOAD_UDP_TS; /* After 2 sync bytes */
		}
		if (len >= (188 * 1) && (ptr[offset + (188 * 0)] == 0x47)) {
			return PAYLOAD_UDP_TS; /* After 1 sync byte */
		}
	}

	if ((lengthBytes > 12) && ((lengthBytes - 12) % 188 == 0)) {
		/* Perfect multiple for RTP wrapped transport packets */
		int len = lengthBytes - 12;
		int offset = 12;
		if ((len >= (188 * 3)) && (ptr[offset + (188 * 0)] == 0x47) && (ptr[offset + (188 * 1)] == 0x47) && (ptr[offset + (188 * 2)] == 0x47)) {
			return PAYLOAD_RTP_TS; /* After 3 sync bytes */
		}
		if ((len >= (188 * 2)) && (ptr[offset + (188 * 0)] == 0x47) && (ptr[offset + (188 * 1)] == 0x47)) {
			return PAYLOAD_RTP_TS; /* After 2 sync bytes */
		}
		if (len >= (188 * 1) && (ptr[offset + (188 * 0)] == 0x47)) {
			return PAYLOAD_RTP_TS; /* After 1 sync byte */
		}
	}

	/* Table 6.1 - Spec A/324:2018 7 Jan 2020 */
	/* Confirm version == 2 and marker == 97 and protocol == 1 */
	if (((ptr[0] & 0xcf) == 0x80) && ((ptr[1] & 0x7f) == 97)) {
		di->a324_found++;
		if (di->a324_found > 2) {
			return PAYLOAD_A324_CTP;
		}
	} else 
	if (((ptr[0] & 0xcf) == 0x80) && ((ptr[1] & 0x7f) == 96)) {
		/* This isn't particularly robust, tighten this up */
		di->smpte2110_video_found++;
		if (di->smpte2110_video_found > 4) {
			return PAYLOAD_SMPTE2110_20_VIDEO;
		}
	} else 
	if (((ptr[0] & 0xcf) == 0x80) && ((ptr[1] & 0x7f) == 98)) {
		/* This isn't particularly robust, tighten this up */
		di->smpte2110_audio_found++;
		if (di->smpte2110_audio_found > 4) {
			return PAYLOAD_SMPTE2110_30_AUDIO;
		}
	} else 
	if (((ptr[0] & 0xcf) == 0x80) && ((ptr[1] & 0x7f) == 100)) {
		/* This isn't particularly robust, tighten this up */
		di->smpte2110_anc_found++;
		if (di->smpte2110_anc_found > 4) {
			return PAYLOAD_SMPTE2110_40_ANC;
		}
	} else {
		di->a324_found = 0;
	}

	if (di->discovery_unidentified++ > 12)
		return PAYLOAD_BYTE_STREAM;

	return PAYLOAD_UNDEFINED;
}

/* Called on the pcap thread, avoid all blocking. */
static void _processPackets_Stats(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr,
	const uint8_t *pkts, uint32_t pktCount, enum payload_type_e payloadType,
	const struct pcap_pkthdr *cb_h, const u_char *cb_pkt, int lengthPayloadBytes,
	struct discovered_item_s *di)
{
	time_t now = time(NULL);

	if (di->iat_last_frame.tv_sec) {
		di->iat_cur_us = ltn_timeval_subtract_us((struct timeval *)&cb_h->ts, &di->iat_last_frame);
		if (di->iat_cur_us <= di->iat_lwm_us)
			di->iat_lwm_us = di->iat_cur_us;
		if (di->iat_cur_us >= di->iat_hwm_us)
			di->iat_hwm_us = di->iat_cur_us;

		/* Track max IAT for the last N seconds, it's reported in the summary/detailed logs. */
		if (di->iat_cur_us > di->iat_hwm_us_last_nsecond_accumulator) {
			di->iat_hwm_us_last_nsecond_accumulator = di->iat_cur_us;
		}
		if ((di->iat_hwm_us_last_nsecond_time + ctx->file_write_interval) <= now) {
			di->iat_hwm_us_last_nsecond_time = now;
			di->iat_hwm_us_last_nsecond = di->iat_hwm_us_last_nsecond_accumulator;
			di->iat_hwm_us_last_nsecond_accumulator = 0;
		}

		ltn_histogram_interval_update_with_value(di->packetIntervals, di->iat_cur_us / 1000);
		throughput_hires_write_i64(di->packetIntervalAverages, 0, di->iat_cur_us / 1000, NULL);
		
		if (di->streamModel &&
			((di->payloadType == PAYLOAD_RTP_TS) || (di->payloadType == PAYLOAD_UDP_TS))) {
			int complete;
			ltntstools_streammodel_write(di->streamModel, pkts, pktCount, &complete);
		}
#if 1
		/* Measure IAT in terms of the following additional bins 10ms and 100ms */
		/* Work thorugh the hires list, calculate the max IAT for each period and maintain a high-watermark */
		/* Write the number of bits and a timestamp into a hirres counter */
		pthread_mutex_lock(&di->bitrateBucketLock);
		throughput_hires_write_i64(di->packetPayloadSizeBits, 0, lengthPayloadBytes * 8, NULL);

		struct timeval nowtv;
		gettimeofday(&nowtv, NULL);

		struct timeval then10ms;
		subtract_ms_from_timeval(&then10ms, &nowtv, 10);
		int64_t bitrate_max_10ms = throughput_hires_sumtotal_i64(di->packetPayloadSizeBits, 0, &then10ms, &nowtv);
		if (di->bitrate_hwm_us_10ms <= bitrate_max_10ms)
			di->bitrate_hwm_us_10ms = bitrate_max_10ms;

		/* Track max IAT for the last N seconds, it's reported in the summary/detailed logs. */
		if (di->bitrate_hwm_us_10ms > di->bitrate_hwm_us_10ms_last_nsecond_accumulator) {
			di->bitrate_hwm_us_10ms_last_nsecond_accumulator = bitrate_max_10ms;
		}
		if ((di->bitrate_hwm_us_10ms_last_nsecond_time + ctx->file_write_interval) <= now) {
			di->bitrate_hwm_us_10ms_last_nsecond_time = now;
			di->bitrate_hwm_us_10ms_last_nsecond = di->bitrate_hwm_us_10ms_last_nsecond_accumulator;
			di->bitrate_hwm_us_10ms_last_nsecond_accumulator = 0;
		}

		struct timeval then100ms;
		subtract_ms_from_timeval(&then100ms, &nowtv, 100);
		int64_t bitrate_max_100ms = throughput_hires_sumtotal_i64(di->packetPayloadSizeBits, 0, &then100ms, &nowtv);
		if (di->bitrate_hwm_us_100ms <= bitrate_max_100ms)
			di->bitrate_hwm_us_100ms = bitrate_max_100ms;

		if (di->bitrate_hwm_us_100ms > di->bitrate_hwm_us_10ms_last_nsecond_accumulator) {
			di->bitrate_hwm_us_100ms_last_nsecond_accumulator = bitrate_max_100ms;
		}
		if ((di->bitrate_hwm_us_100ms_last_nsecond_time + ctx->file_write_interval) <= now) {
			di->bitrate_hwm_us_100ms_last_nsecond_time = now;
			di->bitrate_hwm_us_100ms_last_nsecond = di->bitrate_hwm_us_100ms_last_nsecond_accumulator;
			di->bitrate_hwm_us_100ms_last_nsecond_accumulator = 0;
		}
		pthread_mutex_unlock(&di->bitrateBucketLock);
#endif
#if 0
		struct timeval then1000ms;
		subtract_ms_from_timeval(&then1000ms, &nowtv, 1000);
		int64_t bitrate_max_1000ms = throughput_hires_sumtotal_i64(di->packetPayloadSizeBits, 0, &then1000ms, &nowtv);

		double a = (double)bitrate_max_1000ms / 1000000.0;
		double b = ((double)bitrate_max_100ms * 10) / 1000000.0;
		double c = ((double)bitrate_max_10ms * 100) / 1000000.0;
		printf("br: %" PRIi64 ", br100: %" PRIi64 ", br10: %" PRIi64 "     %6.02f %6.02f %6.02f\n", 
			bitrate_max_1000ms, bitrate_max_100ms * 10, bitrate_max_10ms * 100,
			a, b, c);
#endif
	}
	di->iat_last_frame = cb_h->ts;

	/* If we're detected the LTN version marker, start feeding the packets into the latency detection probe. */
	if ((di->payloadType == PAYLOAD_RTP_TS) || (di->payloadType == PAYLOAD_UDP_TS))
	{
// SEGFAULT
		ltntstools_pid_stats_update(di->stats, pkts, pktCount);

		if (di->isLTNEncoder) {
			/* TODO: This will find the first timestamp in a MPTS and it will be rendered as an identical
			 * measurement for every service in the mux. This would be factually wrong. The right approach
			 * is to have a sense of 'which video pid' the latency is associated with, and render that.
			 */
			ltntstools_probe_ltnencoder_sei_timestamp_query(di->LTNLatencyProbe, pkts, pktCount * 188);
		} else {
			if (ctx->measureSEILatencyAlways) {
				ltntstools_probe_ltnencoder_sei_timestamp_query(di->LTNLatencyProbe, pkts, pktCount * 188);
			}
		}

		if (di->stats->ccErrors != di->statsToUI_ccErrors) {
			if (di->lastStreamCCError != now) {
				di->lastStreamCCError = now;
				display_doc_append_cc_error(&di->doc_stream_log, 0, NULL);
			}
// SEGFAULT
			di->statsToUI_ccErrors = di->stats->ccErrors;
			/* Cache current stats so we can compare the next time around. */
		}

	} else
	if (di->payloadType == PAYLOAD_A324_CTP)
	{
		ltntstools_ctp_stats_update(di->stats, pkts, lengthPayloadBytes);
	} else
	if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO)
	{
		ltntstools_ctp_stats_update(di->stats, pkts, lengthPayloadBytes);
	} else
	if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO)
	{
		ltntstools_ctp_stats_update(di->stats, pkts, lengthPayloadBytes);
	} else
	if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC)
	{
		ltntstools_ctp_stats_update(di->stats, pkts, lengthPayloadBytes);
	} else
	if (di->payloadType == PAYLOAD_BYTE_STREAM)
	{
		ltntstools_bytestream_stats_update(di->stats, pkts, lengthPayloadBytes);
	}
}

/* Called on the stats thread, blocking and stalling is tolerated. */
static void _processPackets_IO(struct tool_context_s *ctx,
	struct ether_header *ethhdr, struct iphdr *iphdr, struct udphdr *udphdr,
	const uint8_t *pkts, uint32_t pktCount, int isRTP,
	const struct pcap_pkthdr *cb_h, const u_char *cb_pkt, int lengthBytes)
{
	struct discovered_item_s *di = discovered_item_findcreate(ctx, ethhdr, iphdr, udphdr);
	if (!di)
		return;

	time_t now;
	time(&now);

	/* Expire any interval averages every few seconds, ro avoid queue growth and memory loss over time. */

	if (now >= di->packetIntervalAveragesLastExpire + 5) {
		di->packetIntervalAveragesLastExpire = now;
		throughput_hires_expire(di->packetIntervalAverages, NULL); /* Expire anything older than 2 seconds. */
		throughput_hires_expire(di->packetPayloadSizeBits, NULL); /* Expire anything older than 2 seconds. */
	}

	if (di->payloadType == PAYLOAD_RTP_TS) {
		if (ntohs(udphdr->len) - 8 - 12 != (7 * 188)) {
        		di->notMultipleOfSevenError++;
        		time(&di->notMultipleOfSevenErrorLastEvent);
		}

		/* Feed the analyzer */
		if (isRTP) {
			/* Extra check, does no harm */
			const struct rtp_hdr *h = (const struct rtp_hdr *)(pkts - 12);

			if (di->rtpAnalyzerCtx.tsArrival == NULL) {
				/* Initialize the rtp context regardless of stream type.
				* We'll only push packets into this for payloadTypes we supported.
				*/
				rtp_analyzer_init(&di->rtpAnalyzerCtx);
			}

			if (ctx->reportRTPHeaders) {
				char stream[128];
				sprintf(stream, "%s", di->srcaddr);
				sprintf(stream + strlen(stream), " -> %s : ", di->dstaddr);

				dprintf(STDOUT_FILENO, "%s", stream);
				for (int i = 0; i < 12; i++) {
					dprintf(STDOUT_FILENO, "%02x ", *(pkts - 12 + i));
				}
				dprintf(STDOUT_FILENO, ": ");

				rtp_analyzer_hdr_dprintf(h, STDOUT_FILENO);
			}

			rtp_hdr_write(&di->rtpAnalyzerCtx, h);

		}

	} else {
		if (ntohs(udphdr->len) - 8 != (7 * 188)) {
        		di->notMultipleOfSevenError++;
        		time(&di->notMultipleOfSevenErrorLastEvent);
		}
	}

	/* Packet Forwarding */
	if (discovered_item_state_get(di, DI_STATE_STREAM_FORWARD_STOP)) {
		discovered_item_state_clr(di, DI_STATE_STREAM_FORWARD_START);
		discovered_item_state_clr(di, DI_STATE_STREAM_FORWARD_STOP);
		discovered_item_state_clr(di, DI_STATE_STREAM_FORWARDING);

		/* Free any resources */
		avio_close(di->forwardAVIO);
	}
	if (discovered_item_state_get(di, DI_STATE_STREAM_FORWARD_START)) {
		discovered_item_state_clr(di, DI_STATE_STREAM_FORWARD_START);
		discovered_item_state_set(di, DI_STATE_STREAM_FORWARDING);

		/* Allocate any resources */
		sprintf(di->forwardURL, "udp://%s:%d?pkt_size=1316&ttl=3",
			ctx->url_forwards[7 - di->forwardSlotNr].addr,
			ctx->url_forwards[7 - di->forwardSlotNr].port);
		int ret = avio_open2(&di->forwardAVIO, di->forwardURL,
			AVIO_FLAG_WRITE | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
		if (ret < 0) {
		}
	}
	if (discovered_item_state_get(di, DI_STATE_STREAM_FORWARDING)) {
		/* Do actual forwarding. */
#if 1
		avio_write(di->forwardAVIO, pkts, pktCount * 188);
#else
		/* Drop all pids except video, so we can measure video pid jitter.
		 * TODO: Hardcoded to 0x100, lab use only.
		 */
		for (int z = 0; z < pktCount * 188; z += 188) {
			uint16_t pidnr = ltntstools_pid(pkts + z);
			if (pidnr == 0x100) {
				avio_write(di->forwardAVIO, pkts + z, 188);
			}
		}
#endif
	}
	/* End: Packet Forwarding */

	/* Recording */
	if (discovered_item_state_get(di, DI_STATE_PCAP_RECORD_STOP)) {
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORD_START);
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORD_STOP);
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORDING);

		if (di->pcapRecorder) {
			ltntstools_segmentwriter_free(di->pcapRecorder);
			di->pcapRecorder = NULL;
		}
	}
	if (discovered_item_state_get(di, DI_STATE_PCAP_RECORD_START)) {
		discovered_item_state_clr(di, DI_STATE_PCAP_RECORD_START);
		discovered_item_state_set(di, DI_STATE_PCAP_RECORDING);

		char prefix[512];
		char dirprefix[256] = "/tmp";
		if (ctx->recordingDir) {
			strcpy(dirprefix, ctx->recordingDir);
		} else {
			struct stat buf;
			if (stat(DEFAULT_STORAGE_LOCATION, &buf) == 0) {
				strcpy(dirprefix, DEFAULT_STORAGE_LOCATION);
			}
		}
	
		char *fn_sep = "-";

		struct stat buf;
		if (stat(dirprefix, &buf) == 0) {
			if (buf.st_mode & S_IFDIR) {
				fn_sep = "/";
			}
		}

		if (ctx->iftype == IF_TYPE_PCAP) {
			sprintf(prefix, "%s%snic_monitor-%s-%s", dirprefix, fn_sep, ctx->ifname, di->dstaddr);
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_FILE) {
			sprintf(prefix, "%s%snic_monitor-%s-%s", dirprefix, fn_sep, "file", di->dstaddr);
		} else
		if (ctx->iftype == IF_TYPE_MPEGTS_AVDEVICE) {
			sprintf(prefix, "%s%snic_monitor-%s-%s", dirprefix, fn_sep, "avdevice", di->dstaddr);
		}

		/* Cleanup the filename so we don't have :, they mess up handing recordings via scp. */
		/* Substitute : for . */
		character_replace(prefix, ':', '.');

		char *suffixNames[2] = { ".pcap", ".ts" };
		char *suffix = suffixNames[0];

		/* A/324  and generic streams are always recorded as PCAP, regardless. */
		if ((di->payloadType == PAYLOAD_BYTE_STREAM ) || (di->payloadType == PAYLOAD_A324_CTP) ||
			(di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) ||
			(di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) ||
			(di->payloadType == PAYLOAD_SMPTE2110_40_ANC)) {
			di->recordAsTS = 0;
		} else {
			/* Other streams, the operator can choose. */
			di->recordAsTS = ctx->recordAsTS;
		}

		if (di->recordAsTS) {
			suffix = suffixNames[1];
		}

		int ret = ltntstools_segmentwriter_alloc(&di->pcapRecorder, prefix, suffix, ctx->recordWithSegments);
		if (ret < 0) {
			fprintf(stderr, "%s() unable to allocate a segment writer\n", __func__);
			exit(1);
		}

		if (!di->recordAsTS) {
			struct pcap_file_header hdr;
			hdr.magic = 0xa1b2c3d4;
			hdr.version_major = PCAP_VERSION_MAJOR;
			hdr.version_minor = PCAP_VERSION_MINOR;
			hdr.thiszone = 0;
			hdr.sigfigs = 0;
			hdr.snaplen = 0x400000;
			hdr.linktype = DLT_EN10MB;
			ltntstools_segmentwriter_set_header(di->pcapRecorder, (const uint8_t *)&hdr, sizeof(hdr));
		}
	}
	if (discovered_item_state_get(di, DI_STATE_PCAP_RECORDING) && !di->recordAsTS) {
		/* Dump the cb_h and cb_pkt payload to disk, via a thread. */
		/* Make sure the timestamps are 4 bytes long, not the native struct size
		 * for the running platform.
		 */

		void *obj = NULL;
		uint8_t *ptr = NULL;
		int ret = ltntstools_segmentwriter_object_alloc(di->pcapRecorder, 16 + cb_h->len, &obj, &ptr);
		if (ret < 0 || !ptr || !obj) {
			return;
		}

		uint8_t *dst = ptr;
		uint8_t *src = (uint8_t *)cb_h;

		memcpy(dst +  0, src +  0, 4);
		memcpy(dst +  4, src +  8, 4);
		memcpy(dst +  8, src + 16, 8);
		memcpy(dst + 16, cb_pkt, cb_h->len);

		ssize_t len = ltntstools_segmentwriter_object_write(di->pcapRecorder, obj);
		if (len < 0) {
			/* Now what? */
			/* Nothing */
		}

		/* Every 5 seconds */
		if (di->lastTimeFSFreeSpaceCheck + 5 <= now) {
			di->lastTimeFSFreeSpaceCheck = now;

			/* Deal with the case where the filesystem is above 90% and we want the recording
			 * to silently terminate. Abort recording if filesystem has 10% freespace or less.
			 */
			double fsfreepct = ltntstools_segmentwriter_get_freespace_pct(di->pcapRecorder);
			if (fsfreepct >= 0.0) {
				if (fsfreepct <= 10.0) {
					if (ctx->skipFreeSpaceCheck == 0) {
						discovered_item_state_set(di, DI_STATE_PCAP_RECORD_STOP);
					}
				}
			}
		}
	}
	if (discovered_item_state_get(di, DI_STATE_PCAP_RECORDING) && di->recordAsTS) {

		ssize_t len = ltntstools_segmentwriter_write(di->pcapRecorder, pkts, pktCount * 188);
		if (len < 0) {
			/* Now what? */
			/* Nothing */
		}

		/* Every 5 seconds */
		if (di->lastTimeFSFreeSpaceCheck + 5 <= now) {
			di->lastTimeFSFreeSpaceCheck = now;

			/* Deal with the case where the filesystem is above 90% and we want the recording
			 * to silently terminate. Abort recording if filesystem has 10% freespace or less.
			 */
			double fsfreepct = ltntstools_segmentwriter_get_freespace_pct(di->pcapRecorder);
			if (fsfreepct >= 0.0) {
				if (fsfreepct <= 10.0) {
					discovered_item_state_set(di, DI_STATE_PCAP_RECORD_STOP);
				}
			}
		}
	}

#if MEDIA_MONITOR
	media_write(pkts, pktCount);
#endif

	nic_monitor_tr101290_write(di, pkts, pktCount);

	pthread_mutex_lock(&di->h264_sliceLock);
	if (di->h264_slices) {
		h264_slice_counter_write(di->h264_slices, pkts, pktCount);

		// We need to decide how to render these, and when.
		//h264_slice_counter_dprintf(di->h264_slices, 0, 0);
	}
	pthread_mutex_unlock(&di->h264_sliceLock);

	pthread_mutex_lock(&di->h264_metadataLock);
	if (di->h264_metadata_parser) {
		int complete;
		ltntstools_h264_codec_metadata_write(di->h264_metadata_parser, pkts, pktCount, &complete);

		if (complete) {
			struct h264_codec_metadata_results_s r;
			if (ltntstools_h264_codec_metadata_query(di->h264_metadata_parser, &r) == 0) {
				strcpy(&di->h264_video_colorspace[0], &r.sps.video_colorspace_ascii[0]);
				strcpy(&di->h264_video_format[0], &r.sps.video_format_ascii[0]);
			}
		}
	}
	pthread_mutex_unlock(&di->h264_metadataLock);

	pthread_mutex_lock(&di->h265_metadataLock);
	if (di->h265_metadata_parser) {
		int complete;
		ltntstools_h265_codec_metadata_write(di->h265_metadata_parser, pkts, pktCount, &complete);

		if (complete) {
			struct h265_codec_metadata_results_s r;
			if (ltntstools_h265_codec_metadata_query(di->h265_metadata_parser, &r) == 0) {
				strcpy(&di->h265_video_colorspace[0], &r.video_colorspace_ascii[0]);
				strcpy(&di->h265_video_format[0], &r.video_format_ascii[0]);
			}
		}
	}
	pthread_mutex_unlock(&di->h265_metadataLock);

	discovered_item_warningindicators_update(ctx, di);
}

/* Called on the UI stream, and writes files to disk, handles recordings etc.
 * You can stall this thread a little, most of the work done here is designed to be blocking,
 * sleeping (a little), io writes, non-realtime work.
 */
static void pcap_io_process(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt) 
{
	int isRTP = 0;

	if (h->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return;

	struct ether_header *eth = (struct ether_header *)pkt;
	if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		struct iphdr *ip = (struct iphdr *)((u_char *)eth + sizeof(struct ether_header));

#ifdef __APPLE__
		if (ip->ip_p != IPPROTO_UDP)
			return;
#endif
#ifdef __linux__
		if (ip->protocol != IPPROTO_UDP)
			return;
#endif

		struct udphdr *udp = (struct udphdr *)((u_char *)ip + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udp + sizeof(struct udphdr));

		if (ctx->verbose) {
			struct in_addr dstaddr, srcaddr;
#ifdef __APPLE__
			srcaddr.s_addr = ip->ip_src.s_addr;
			dstaddr.s_addr = ip->ip_dst.s_addr;
#endif
#ifdef __linux__
			srcaddr.s_addr = ip->saddr;
			dstaddr.s_addr = ip->daddr;
#endif

			char src[24], dst[24];
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udp->source));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udp->dest));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				src, dst,
				ntohs(udp->len),
				ptr[0], ptr[1], ptr[2], ptr[3]);
			//if (ntohs(udp->dest) == 4100)
			{
				for (int i = 0; i < 40; i++)
					printf("%02x ", ptr[i]);
				printf("\n");
			}
		}

		/* TODO: Handle RTP with FEC correctly. */

		if (ptr[0] != 0x47) {
			/* Make a rash assumption that's it's RTP where possible. */
			if (ptr[12] == 0x47) {
				ptr += 12;
				isRTP = 1;
			}
		}

		/* TS Packet, almost certainly */
		/* We can safely assume there are len / 188 packets. */
		int pktCount = ntohs(udp->len) / 188;
		int lengthBytes = ntohs(udp->len);
		_processPackets_IO(ctx, eth, ip, udp, ptr, pktCount, isRTP, h, pkt, lengthBytes);
	}
}

/* Called on the pcap thread. don't linger, be swift else risk, pcap buffer loss under load. */
void pcap_update_statistics(struct tool_context_s *ctx, const struct pcap_pkthdr *h, const u_char *pkt) 
{ 
	enum payload_type_e payloadType = PAYLOAD_UNDEFINED;

	if (h->len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return;

	struct ether_header *ethhdr = (struct ether_header *)pkt;
	if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
		struct iphdr *iphdr = (struct iphdr *)((u_char *)ethhdr + sizeof(struct ether_header));

#ifdef __APPLE__
		if (iphdr->ip_p != IPPROTO_UDP)
			return;
#endif
#ifdef __linux__
		if (iphdr->protocol != IPPROTO_UDP)
			return;
#endif

		struct udphdr *udphdr = (struct udphdr *)((u_char *)iphdr + sizeof(struct iphdr));
		uint8_t *ptr = (uint8_t *)((uint8_t *)udphdr + sizeof(struct udphdr));

		if (ctx->verbose > 2) {
			struct in_addr dstaddr, srcaddr;
#ifdef __APPLE__
			srcaddr.s_addr = iphdr->ip_src.s_addr;
			dstaddr.s_addr = iphdr->ip_dst.s_addr;
#endif
#ifdef __linux__
			srcaddr.s_addr = iphdr->saddr;
			dstaddr.s_addr = iphdr->daddr;
#endif

			char src[24], dst[24];
			sprintf(src, "%s:%d", inet_ntoa(srcaddr), ntohs(udphdr->source));
			sprintf(dst, "%s:%d", inet_ntoa(dstaddr), ntohs(udphdr->dest));

			printf("%s -> %s : %4d : %02x %02x %02x %02x\n",
				src, dst,
				ntohs(udphdr->len),
				ptr[0], ptr[1], ptr[2], ptr[3]);
		}

		struct discovered_item_s *di = discovered_item_findcreate(ctx, ethhdr, iphdr, udphdr);
		if (!di)
			return;

		/* Flag the fact we've seen the object have data, at this time.
		 * lastUpdated will be noticed during housekeeping and lack of activity
		 * on a di object triggers other actions.
		 */
		di->lastUpdated = time(NULL);

		int lengthPayloadBytes = ntohs(udphdr->len) - sizeof(struct udphdr);
#if 0
		/* Mangle incoming stream so we can check our payload detection code */
		/* Trash anything on port 4011 */
		if (ntohs(udphdr->dest) == 4011) {
			ptr += 5;
			lengthPayloadBytes -= 5;
		}
#endif

		/* TODO: Handle RTP with FEC correctly. */
		if (di->payloadType == PAYLOAD_UNDEFINED)
			di->payloadType = determinePayloadType(di, ptr, lengthPayloadBytes);

		if (di->payloadType == PAYLOAD_RTP_TS) {
			lengthPayloadBytes -= 12;
			ptr += 12;
		}

		/* TS Packet, almost certainly */
		/* We can safely assume there are len / 188 packets. */
		int pktCount = lengthPayloadBytes / 188;
		_processPackets_Stats(ctx, ethhdr, iphdr, udphdr, ptr, pktCount, payloadType, h, pkt, lengthPayloadBytes, di);
	}
}

/* Return the number of list items processed.
 * We're being called on the stats thread, so while we're
 * expected to take the listpcap lock, we do so for the shortest
 * amount of time possible, then do all of the expensive
 * analysis and filewriting tasks WHILE NOT holding the mutex.
 */
int pcap_queue_service(struct tool_context_s *ctx)
{
	int count = 0;

	pthread_mutex_lock(&ctx->lockpcap);
	if (xorg_list_is_empty(&ctx->listpcapUsed)) {
		pthread_mutex_unlock(&ctx->lockpcap);
		return count;
	}

	/* Move all of the Used buffers into a temporary list, its quick. */
	struct xorg_list items;
	xorg_list_init(&items);

	struct pcap_item_s *item = NULL;
	while (!xorg_list_is_empty(&ctx->listpcapUsed)) {
		item = xorg_list_first_entry(&ctx->listpcapUsed, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapUsedDepth--;
		xorg_list_append(&item->list, &items);
		count++;
	}
	pthread_mutex_unlock(&ctx->lockpcap);

	/* Now, relatively, we can take as long as we like to process 'items'. */
	while (!xorg_list_is_empty(&items)) {
		item = xorg_list_first_entry(&items, struct pcap_item_s, list);
		xorg_list_del(&item->list);

		if (item->h && item->pkt) {
			/* safety */
			pcap_io_process(ctx, item->h, item->pkt);
		} else {
			ctx->pcap_mangled_list_items++;
		}

		/* back on the free list */
		pthread_mutex_lock(&ctx->lockpcap);
		xorg_list_append(&item->list, &ctx->listpcapFree);
		ctx->listpcapFreeDepth++;
		pthread_mutex_unlock(&ctx->lockpcap);
	}

	time_t now;
	time(&now);

	if (ctx->rebalance_last_buffer_time != now) {
		ctx->rebalance_last_buffer_time = now;
		ctx->rebalance_last_buffers_used = ctx->rebalance_buffers_used;
		ctx->rebalance_buffers_used = 0;
	}
        ctx->rebalance_buffers_used += count;

	return count;
}

static void pcap_queue_free_reduce(struct tool_context_s *ctx, int bufferCount)
{
	pthread_mutex_lock(&ctx->lockpcap);
	while (bufferCount-- > 0 && ctx->listpcapFreeDepth > QUEUE_MIN) {
		if (xorg_list_is_empty(&ctx->listpcapFree))
			break;
		struct pcap_item_s *item = xorg_list_first_entry(&ctx->listpcapFree, struct pcap_item_s, list);
		xorg_list_del(&item->list);
		ctx->listpcapFreeDepth--;

		free(item->h);
		free(item->pkt);
		free(item);
	}
	pthread_mutex_unlock(&ctx->lockpcap);
}

/* Goal: To prevent the amount of free pcap buffers from remaining excessively
 * high after a significant I/O stall has caused additional free
 * buffers to be created, and they're now largely idle and consuming
 * ram. Remove them.
 */
int pcap_queue_rebalance(struct tool_context_s *ctx)
{
	time_t now;
	time(&now);

	if (ctx->rebalance_queue_time_last + 5 < now) {
		ctx->rebalance_queue_time_last = now;

		/* Try to keep 50% free buffers for platform stall/spikes. */
		double demand = (double)ctx->rebalance_last_buffers_used * 0.15;
		double avail = (double)ctx->listpcapFreeDepth;
		if (avail > demand) {
			double balance = avail - demand;
			if (balance > 100000) {
				pcap_queue_free_reduce(ctx, 100000);
			} else
			if (balance > 50000) {
				pcap_queue_free_reduce(ctx, 50000);
			} else
			if (balance > 20000) {
				pcap_queue_free_reduce(ctx, 20000);
			} else
			if (balance > 10000) {
				pcap_queue_free_reduce(ctx, 10000);
			}
		}
	}

	return 0;
}

