#include "nic_monitor.h"

#include <errno.h>

extern int ltnpthread_setname_np(pthread_t thread, const char *name);

static void add_json_int64(json_object *obj, const char *name, int64_t v)
{
	json_object_object_add(obj, name, json_object_new_int64(v));
}

static void add_json_uint64(json_object *obj, const char *name, uint64_t v)
{
	json_object_object_add(obj, name, json_object_new_int64((int64_t)v));
}

static void add_json_pid_pair(json_object *obj, const char *name, uint32_t pid)
{
	char key[64];
	char pid_hex[16];
	snprintf(pid_hex, sizeof(pid_hex), "0x%04x", pid);
	json_object_object_add(obj, name, json_object_new_int64(pid));
	snprintf(key, sizeof(key), "%sHex", name);
	json_object_object_add(obj, key, json_object_new_string(pid_hex));
}

static void add_json_stream_type_pair(json_object *obj, const char *name, uint32_t stream_type)
{
	char key[64];
	char type_hex[16];
	snprintf(type_hex, sizeof(type_hex), "0x%02x", stream_type);
	json_object_object_add(obj, name, json_object_new_int64(stream_type));
	snprintf(key, sizeof(key), "%sHex", name);
	json_object_object_add(obj, key, json_object_new_string(type_hex));
}

static char *hex_encode(const uint8_t *src, size_t lengthBytes)
{
	static const char hex[] = "0123456789abcdef";
	char *dst = malloc((lengthBytes * 2) + 1);
	if (!dst)
		return NULL;

	for (size_t i = 0; i < lengthBytes; i++) {
		dst[i * 2] = hex[(src[i] >> 4) & 0x0f];
		dst[(i * 2) + 1] = hex[src[i] & 0x0f];
	}
	dst[lengthBytes * 2] = 0;
	return dst;
}

static int stream_uses_pid_stats(struct discovered_item_s *di)
{
	return di->payloadType == PAYLOAD_UDP_TS ||
		di->payloadType == PAYLOAD_RTP_TS ||
		di->payloadType == PAYLOAD_SRT_TS;
}

static void stream_bitrate(struct discovered_item_s *di, double *mbps, uint32_t *bps)
{
	if (stream_uses_pid_stats(di)) {
		*mbps = ltntstools_pid_stats_stream_get_mbps(di->stats);
		*bps = ltntstools_pid_stats_stream_get_bps(di->stats);
		return;
	}

	if (di->payloadType == PAYLOAD_A324_CTP ||
		di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO ||
		di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO ||
		di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
		*mbps = ltntstools_ctp_stats_stream_get_mbps(di->stats);
		*bps = ltntstools_ctp_stats_stream_get_bps(di->stats);
		return;
	}

	*mbps = ltntstools_bytestream_stats_stream_get_mbps(di->stats);
	*bps = ltntstools_bytestream_stats_stream_get_bps(di->stats);
}

static json_object *stream_identity_json(struct discovered_item_s *di)
{
	json_object *obj = json_object_new_object();
	json_object_object_add(obj, "id", json_object_new_string(di->dstaddr));
	json_object_object_add(obj, "protocolType", json_object_new_string(payloadTypeDesc(di->payloadType)));
	json_object_object_add(obj, "source", json_object_new_string(di->srcaddr));
	json_object_object_add(obj, "destination", json_object_new_string(di->dstaddr));
	add_json_int64(obj, "firstSeenUnix", di->firstSeen);
	add_json_int64(obj, "lastUpdatedUnix", di->lastUpdated);
	return obj;
}

static void add_flag_definition(json_object *defs, int position, const char *symbol, const char *name, const char *description)
{
	json_object *def = json_object_new_object();
	add_json_int64(def, "position", position);
	json_object_object_add(def, "symbol", json_object_new_string(symbol));
	json_object_object_add(def, "name", json_object_new_string(name));
	json_object_object_add(def, "description", json_object_new_string(description));
	json_object_object_add(defs, symbol, def);
}

static json_object *warning_flag_definitions_json(void)
{
	json_object *defs = json_object_new_object();

	add_flag_definition(defs, 0, "I", "iatHighWaterMarkExceeded",
		"IAT high-water mark exceeded the configured -I threshold.");
	add_flag_definition(defs, 1, "D", "hiddenDuplicateDestination",
		"One or more duplicate streams share this destination and are hidden.");
	add_flag_definition(defs, 2, "P", "packetSizeAnomaly",
		"UDP payload size was not a multiple of 7 * 188 byte transport packets.");
	add_flag_definition(defs, 3, "T", "transportStreamPayload",
		"Payload is detected as MPEG transport stream.");
	add_flag_definition(defs, 2, "E", "encryptedSrt",
		"Payload is encrypted SRT data.");
	add_flag_definition(defs, -1, "?", "unknownPayload",
		"Payload type is unknown or does not have a defined flag layout.");
	add_flag_definition(defs, -1, "-", "notSet",
		"No warning or state is set for this position.");

	return defs;
}

static const char *audio_type_description(unsigned int audio_type)
{
	switch (audio_type) {
	case 0:
		return "None";
	case 1:
		return "Clean effects";
	case 2:
		return "Hearing impaired";
	case 3:
		return "Visual impaired commentary";
	default:
		return "Reserved";
	}
}

static int stream_model_unavailable_reason(struct discovered_item_s *di, const char **reason)
{
	if (di->payloadType == PAYLOAD_SMPTE2110_20_VIDEO) {
		*reason = "Service Information Report not available for SMPTE2110-20 Video streams";
		return 1;
	}
	if (di->payloadType == PAYLOAD_SRT_CTRL) {
		*reason = "Service Information Report not available for SRT flow control channels";
		return 1;
	}
	if (di->payloadType == PAYLOAD_SRT_ENCRYPTED) {
		*reason = "Service Information Report not available for SRT encrypted channels";
		return 1;
	}
	if (di->payloadType == PAYLOAD_SMPTE2110_30_AUDIO) {
		*reason = "Service Information Report not available for SMPTE2110-30 Audio streams";
		return 1;
	}
	if (di->payloadType == PAYLOAD_SMPTE2110_40_ANC) {
		*reason = "Service Information Report not available for SMPTE2110-40 Ancillary Data streams";
		return 1;
	}
	if (di->payloadType == PAYLOAD_A324_CTP) {
		*reason = "Service Information Report not available for A/324 Studio Transmitter Link CTP streams";
		return 1;
	}
	if (di->payloadType == PAYLOAD_BYTE_STREAM) {
		*reason = "Service Information Report not available for unidentified byte streams";
		return 1;
	}

	return 0;
}

static void prime_pcr_pids_from_model(struct discovered_item_s *di)
{
	struct ltntstools_pat_s *m = NULL;

	if (!di->streamModel || ltntstools_streammodel_query_model(di->streamModel, &m) != 0 || !m)
		return;

	for (unsigned int p = 0; p < m->program_count; p++) {
		if (m->programs[p].program_number > 0 && m->programs[p].pmt.PCR_PID)
			ltntstools_pid_stats_pid_set_contains_pcr(di->stats, m->programs[p].pmt.PCR_PID);
	}

	ltntstools_pat_free(m);
}

static json_object *stream_model_json(struct discovered_item_s *di)
{
	json_object *stream = stream_identity_json(di);
	const char *reason = NULL;

	json_object_object_add(stream, "available", json_object_new_boolean(0));
	if (stream_model_unavailable_reason(di, &reason)) {
		json_object_object_add(stream, "reason", json_object_new_string(reason));
		return stream;
	}
	if (!di->streamModel) {
		json_object_object_add(stream, "reason", json_object_new_string("stream model analyzer is not available"));
		return stream;
	}

	struct ltntstools_pat_s *m = NULL;
	if (ltntstools_streammodel_query_model(di->streamModel, &m) != 0 || !m) {
		json_object_object_add(stream, "reason", json_object_new_string("stream model has not been discovered yet"));
		return stream;
	}

	json_object_object_add(stream, "available", json_object_new_boolean(1));
	json_object_object_add(stream, "multiplexType", json_object_new_string(ltntstools_streammodel_is_model_mpts(di->streamModel, m) ? "MPTS" : "SPTS"));
	add_json_int64(stream, "transportStreamId", m->transport_stream_id);
	add_json_int64(stream, "version", m->version_number);
	add_json_int64(stream, "currentNextIndicator", m->current_next_indicator);
	add_json_int64(stream, "programCount", m->program_count);

	json_object *programs = json_object_new_array();
	json_object_object_add(stream, "programs", programs);

	for (unsigned int p = 0; p < m->program_count; p++) {
		struct ltntstools_pat_program_s *program = &m->programs[p];
		json_object *program_json = json_object_new_object();
		json_object_array_add(programs, program_json);

		add_json_int64(program_json, "programNumber", program->program_number);
		json_object_object_add(program_json, "isNetworkInformationTable", json_object_new_boolean(program->program_number == 0));
		add_json_pid_pair(program_json, "pmtPid", program->program_map_PID);

		if (program->program_number == 0) {
			json_object_object_add(program_json, "streams", json_object_new_array());
			continue;
		}

		add_json_int64(program_json, "pmtVersion", program->pmt.version_number);
		add_json_int64(program_json, "pmtCurrentNextIndicator", program->pmt.current_next_indicator);
		add_json_pid_pair(program_json, "pcrPid", program->pmt.PCR_PID);
		ltntstools_pid_stats_pid_set_contains_pcr(di->stats, program->pmt.PCR_PID);
		add_json_int64(program_json, "streamCount", program->pmt.stream_count);
		json_object_object_add(program_json, "serviceName", json_object_new_string((char *)program->service_name));
		json_object_object_add(program_json, "serviceProvider", json_object_new_string((char *)program->service_provider));
		add_json_int64(program_json, "serviceId", program->service_id);
		add_json_int64(program_json, "serviceType", program->service_type);

		int has_scte35 = ltntstools_descriptor_list_contains_scte35_cue_registration(&program->pmt.descr_list);
		int has_smpte2038 = 0;
		json_object_object_add(program_json, "hasScte35Registration", json_object_new_boolean(has_scte35 != 0));

		int64_t pcr = ltntstools_pid_stats_pid_get_pcr(di->stats, program->pmt.PCR_PID);
		add_json_int64(program_json, "pcr", pcr);
		char *pcr_ascii = NULL;
		ltntstools_pcr_to_ascii(&pcr_ascii, pcr);
		if (pcr_ascii) {
			json_object_object_add(program_json, "pcrAscii", json_object_new_string(pcr_ascii));
			free(pcr_ascii);
		}

		unsigned int major = 0, minor = 0, patch = 0;
		int encoder_ret = ltntstools_descriptor_list_contains_ltn_encoder_sw_version(&program->pmt.descr_list, &major, &minor, &patch);
		if (encoder_ret == 1) {
			json_object *encoder = json_object_new_object();
			json_object_object_add(program_json, "ltnEncoder", encoder);
			add_json_int64(encoder, "major", major);
			add_json_int64(encoder, "minor", minor);
			add_json_int64(encoder, "patch", patch);
			add_json_int64(encoder, "latencyMs", ltntstools_probe_ltnencoder_get_total_latency(di->LTNLatencyProbe));
		}

		json_object *streams = json_object_new_array();
		json_object_object_add(program_json, "streams", streams);
		for (unsigned int s = 0; s < program->pmt.stream_count; s++) {
			struct ltntstools_pmt_entry_s *es = &program->pmt.streams[s];
			json_object *es_json = json_object_new_object();
			json_object_array_add(streams, es_json);

			add_json_pid_pair(es_json, "pid", es->elementary_PID);
			add_json_stream_type_pair(es_json, "streamType", es->stream_type);
			json_object_object_add(es_json, "description", json_object_new_string(ltntstools_GetESPayloadTypeDescription(es->stream_type)));

			unsigned int audio_type = 0;
			unsigned char lbl[16] = { 0 };
			if (ltntstools_descriptor_list_contains_iso639_audio_descriptor(&es->descr_list, &lbl[0], &audio_type)) {
				json_object *audio = json_object_new_object();
				json_object_object_add(es_json, "audio", audio);
				json_object_object_add(audio, "language", json_object_new_string((char *)lbl));
				add_json_int64(audio, "type", audio_type);
				json_object_object_add(audio, "typeDescription", json_object_new_string(audio_type_description(audio_type)));
			}

			if (es->stream_type == 0x06 && ltntstools_descriptor_list_contains_smpte2038_registration(&es->descr_list)) {
				has_smpte2038 = 1;
				json_object_object_add(es_json, "hasSmpte2038Registration", json_object_new_boolean(1));
			} else {
				json_object_object_add(es_json, "hasSmpte2038Registration", json_object_new_boolean(0));
			}
		}

		json_object_object_add(program_json, "hasSmpte2038Registration", json_object_new_boolean(has_smpte2038 != 0));
	}

	ltntstools_pat_free(m);
	return stream;
}

static json_object *clock_report_json(struct discovered_item_s *di)
{
	json_object *stream = stream_identity_json(di);
	json_object *pcr_pids = json_object_new_array();
	const char *reason = NULL;

	json_object_object_add(stream, "available", json_object_new_boolean(0));
	json_object_object_add(stream, "pcrPids", pcr_pids);
	if (stream_model_unavailable_reason(di, &reason)) {
		json_object_object_add(stream, "reason", json_object_new_string(reason));
		return stream;
	}

	prime_pcr_pids_from_model(di);

	struct ltntstools_pid_statistics_s *pid;
	ltntstools_stats_for_each_pid(di->stats, i, pid) {
		if (!pid->enabled)
			continue;
		if (!pid->hasPCR)
			continue;

		json_object *item = json_object_new_object();
		json_object_array_add(pcr_pids, item);

		add_json_pid_pair(item, "pid", i);
		add_json_int64(item, "pcr", ltntstools_pid_stats_pid_get_pcr(di->stats, i));

		char *pcr_ascii = NULL;
		ltntstools_pcr_to_ascii(&pcr_ascii, ltntstools_pid_stats_pid_get_pcr(di->stats, i));
		if (pcr_ascii) {
			json_object_object_add(item, "pcrAscii", json_object_new_string(pcr_ascii));
			free(pcr_ascii);
		}

		char *s = NULL;
		if (pid->pcrTickIntervals) {
			ltn_histogram_interval_print_buf(&s, pid->pcrTickIntervals, 0);
		}
		if (s) {
			json_object_object_add(item, "pcrTickIntervalsText", json_object_new_string(s));
			free(s);
			s = NULL;
		} else {
			json_object_object_add(item, "pcrTickIntervalsText", json_object_new_string(""));
		}

		if (pid->pcrWallDrift) {
			ltn_histogram_interval_print_buf(&s, pid->pcrWallDrift, 0);
		}
		if (s) {
			json_object_object_add(item, "pcrWallDriftText", json_object_new_string(s));
			free(s);
			s = NULL;
		} else {
			json_object_object_add(item, "pcrWallDriftText", json_object_new_string(""));
		}
	}

	if (json_object_array_length(pcr_pids) > 0) {
		json_object_object_add(stream, "available", json_object_new_boolean(1));
	} else {
		json_object_object_add(stream, "reason", json_object_new_string("no PCR clock statistics discovered yet"));
	}

	return stream;
}

static json_object *stream_log_json(struct discovered_item_s *di)
{
	json_object *stream = stream_identity_json(di);
	json_object *lines = json_object_new_array();

	pthread_mutex_lock(&di->doc_stream_log.lock);
	add_json_int64(stream, "lineCount", di->doc_stream_log.lineCount);
	add_json_int64(stream, "displayLineFrom", di->doc_stream_log.displayLineFrom);
	add_json_int64(stream, "pageSize", di->doc_stream_log.pageSize);
	add_json_int64(stream, "maxPageSize", di->doc_stream_log.maxPageSize);
	for (int i = 0; i < di->doc_stream_log.lineCount; i++) {
		json_object_array_add(lines, json_object_new_string((char *)di->doc_stream_log.lines[i]));
	}
	pthread_mutex_unlock(&di->doc_stream_log.lock);

	json_object_object_add(stream, "lines", lines);
	return stream;
}

static json_object *iat_histogram_json(struct tool_context_s *ctx, struct discovered_item_s *di)
{
	json_object *stream = stream_identity_json(di);
	char *histogram = NULL;

	json_object_object_add(stream, "histogramText", json_object_new_string(""));
	if (di->packetIntervals) {
		ltn_histogram_interval_print_buf(&histogram, di->packetIntervals, 0);
	}
	if (histogram) {
		json_object_object_del(stream, "histogramText");
		json_object_object_add(stream, "histogramText", json_object_new_string(histogram));
		free(histogram);
	}

	add_json_int64(stream, "iatLowWaterMarkUs", di->iat_lwm_us);
	add_json_int64(stream, "iatCurrentUs", di->iat_cur_us);
	add_json_int64(stream, "iatHighWaterMarkUs", di->iat_hwm_us);
	add_json_int64(stream, "iatHighWaterMarkMs", di->iat_hwm_us / 1000);
	add_json_int64(stream, "iatHighWaterMarkLastWindowUs", di->iat_hwm_us_last_nsecond);
	add_json_int64(stream, "iatHighWaterMarkLastWindowMs", di->iat_hwm_us_last_nsecond / 1000);

	pthread_mutex_lock(&di->bitrateBucketLock);
	double burst10msMbps = ((double)di->bitrate_hwm_us_10ms_last_nsecond * 100.0) / 1000000.0;
	double burst100msMbps = ((double)di->bitrate_hwm_us_100ms_last_nsecond * 10.0) / 1000000.0;
	add_json_int64(stream, "bitrateHighWaterMark10msBps", di->bitrate_hwm_us_10ms_last_nsecond * 100);
	add_json_int64(stream, "bitrateHighWaterMark100msBps", di->bitrate_hwm_us_100ms_last_nsecond * 10);
	pthread_mutex_unlock(&di->bitrateBucketLock);

	json_object_object_add(stream, "bitrateHighWaterMark10msMbps", json_object_new_double(burst10msMbps));
	json_object_object_add(stream, "bitrateHighWaterMark100msMbps", json_object_new_double(burst100msMbps));
	json_object_object_add(stream, "microburstMeasurementEnabled", json_object_new_boolean(ctx->reportMicrobursts != 0));

	return stream;
}

static json_object *scte35_json(struct discovered_item_s *di, time_t now)
{
	json_object *stream = stream_identity_json(di);
	json_object *pids = json_object_new_array();
	json_object *messages = json_object_new_array();

	json_object_object_add(stream, "historySeconds", json_object_new_int64(SCTE35_HISTORY_SECONDS));
	json_object_object_add(stream, "pids", pids);
	json_object_object_add(stream, "messages", messages);

	pthread_mutex_lock(&di->scte35Lock);
	scte35_monitor_prune(di, now);

	struct scte35_pid_item_s *pidItem = NULL;
	xorg_list_for_each_entry(pidItem, &di->listSCTE35Pids, list) {
		json_object *pid_json = json_object_new_object();
		json_object_array_add(pids, pid_json);
		add_json_pid_pair(pid_json, "pid", pidItem->pid);
		add_json_pid_pair(pid_json, "videoPid", pidItem->videoPid);
		add_json_int64(pid_json, "messageCount", pidItem->messageCount);
		add_json_int64(pid_json, "lastVideoPTS", pidItem->lastVideoPTS);
	}

	struct scte35_message_item_s *msg = NULL;
	xorg_list_for_each_entry(msg, &di->listSCTE35Messages, list) {
		json_object *msg_json = json_object_new_object();
		json_object_array_add(messages, msg_json);

		add_json_uint64(msg_json, "sequenceNumber", msg->sequenceNumber);
		add_json_int64(msg_json, "receivedAtUnix", msg->receivedAt);
		add_json_int64(msg_json, "ageSeconds", now - msg->receivedAt);
		add_json_pid_pair(msg_json, "pid", msg->pid);
		add_json_pid_pair(msg_json, "videoPid", msg->videoPid);
		add_json_int64(msg_json, "videoPTS", msg->videoPTS);
		json_object_object_add(msg_json, "crcValid", json_object_new_boolean(msg->crcValid != 0));
		json_object_object_add(msg_json, "parseOk", json_object_new_boolean(msg->parseOk != 0));
		add_json_int64(msg_json, "sectionLengthBytes", msg->sectionLengthBytes);

		char *hex = hex_encode(msg->section, msg->sectionLengthBytes);
		if (hex) {
			json_object_object_add(msg_json, "rawSectionHex", json_object_new_string(hex));
			free(hex);
		}

		if (msg->json) {
			json_object *decoded = json_tokener_parse(msg->json);
			if (decoded) {
				json_object_object_add(msg_json, "decoded", decoded);
			} else {
				json_object_object_add(msg_json, "decodedText", json_object_new_string(msg->json));
			}
		}
	}

	add_json_int64(stream, "pidCount", json_object_array_length(pids));
	add_json_int64(stream, "messageCount", json_object_array_length(messages));

	pthread_mutex_unlock(&di->scte35Lock);

	return stream;
}

json_object *rest_api_transport_streams_json(struct tool_context_s *ctx)
{
	json_object *root = json_object_new_object();
	json_object *streams = json_object_new_array();
	time_t now = time(NULL);

	json_object_object_add(root, "timestampUnix", json_object_new_int64(now));
	json_object_object_add(root, "interface", json_object_new_string(ctx->ifname ? ctx->ifname : ""));
	add_json_int64(root, "iatThresholdMs", ctx->iatMax);
	json_object_object_add(root, "flagDefinitions", warning_flag_definitions_json());
	json_object_object_add(root, "streams", streams);

	pthread_mutex_lock(&ctx->lock);
	struct discovered_item_s *di = NULL;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;

		double mbps = 0.0;
		uint32_t bps = 0;
		stream_bitrate(di, &mbps, &bps);

		json_object *item = stream_identity_json(di);
		json_object_object_add(item, "bitrateMbps", json_object_new_double(mbps));
		add_json_int64(item, "bitrateBps", bps);
		add_json_uint64(item, "transportPackets", ltntstools_pid_stats_stream_get_packet_count(di->stats));
		add_json_uint64(item, "ccErrors", ltntstools_pid_stats_stream_get_cc_errors(di->stats));
		add_json_int64(item, "iatHighWaterMarkMs", di->iat_hwm_us / 1000);
		add_json_int64(item, "iatHighWaterMarkUs", di->iat_hwm_us);
		json_object_object_add(item, "flags", json_object_new_string(di->warningIndicatorLabel));
		json_object_object_add(item, "selected", json_object_new_boolean(discovered_item_state_get(di, DI_STATE_SELECTED) != 0));
		json_object_object_add(item, "recording", json_object_new_boolean(discovered_item_state_get(di, DI_STATE_PCAP_RECORDING) != 0));
		json_object_object_add(item, "forwarding", json_object_new_boolean(discovered_item_state_get(di, DI_STATE_STREAM_FORWARDING) != 0));
		add_json_uint64(item, "srtRetransmissions", di->srt_retransmittion_count);
		json_object_array_add(streams, item);
	}
	pthread_mutex_unlock(&ctx->lock);

	return root;
}

json_object *rest_api_transport_pids_json(struct tool_context_s *ctx)
{
	json_object *root = json_object_new_object();
	json_object *streams = json_object_new_array();
	time_t now = time(NULL);

	json_object_object_add(root, "timestampUnix", json_object_new_int64(now));
	json_object_object_add(root, "interface", json_object_new_string(ctx->ifname ? ctx->ifname : ""));
	json_object_object_add(root, "streams", streams);

	pthread_mutex_lock(&ctx->lock);
	struct discovered_item_s *di = NULL;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;

		json_object *stream = stream_identity_json(di);
		json_object *pids = json_object_new_array();
		json_object_object_add(stream, "pids", pids);

		struct ltntstools_pid_statistics_s *pid;
		ltntstools_stats_for_each_pid(di->stats, i, pid) {
			if (!pid->enabled)
				continue;

			char pid_hex[16];
			snprintf(pid_hex, sizeof(pid_hex), "0x%04x", i);

			json_object *item = json_object_new_object();
			add_json_int64(item, "pid", i);
			json_object_object_add(item, "pidHex", json_object_new_string(pid_hex));
			json_object_object_add(item, "bitrateMbps", json_object_new_double(ltntstools_pid_stats_pid_get_mbps(di->stats, i)));
			add_json_uint64(item, "transportPackets", ltntstools_pid_stats_pid_get_packet_count(di->stats, i));
			add_json_uint64(item, "ccErrors", ltntstools_pid_stats_pid_get_cc_errors(di->stats, i));
			add_json_uint64(item, "teiErrors", ltntstools_pid_stats_pid_get_tei_errors(di->stats, i));
			json_object_array_add(pids, item);
		}

		json_object_array_add(streams, stream);
	}
	pthread_mutex_unlock(&ctx->lock);

	return root;
}

json_object *rest_api_stream_models_json(struct tool_context_s *ctx)
{
	json_object *root = json_object_new_object();
	json_object *streams = json_object_new_array();
	time_t now = time(NULL);

	json_object_object_add(root, "timestampUnix", json_object_new_int64(now));
	json_object_object_add(root, "interface", json_object_new_string(ctx->ifname ? ctx->ifname : ""));
	json_object_object_add(root, "streams", streams);

	pthread_mutex_lock(&ctx->lock);
	struct discovered_item_s *di = NULL;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;

		json_object_array_add(streams, stream_model_json(di));
	}
	pthread_mutex_unlock(&ctx->lock);

	return root;
}

json_object *rest_api_stream_logs_json(struct tool_context_s *ctx)
{
	json_object *root = json_object_new_object();
	json_object *streams = json_object_new_array();
	time_t now = time(NULL);

	json_object_object_add(root, "timestampUnix", json_object_new_int64(now));
	json_object_object_add(root, "interface", json_object_new_string(ctx->ifname ? ctx->ifname : ""));
	json_object_object_add(root, "streams", streams);

	pthread_mutex_lock(&ctx->lock);
	struct discovered_item_s *di = NULL;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;

		json_object_array_add(streams, stream_log_json(di));
	}
	pthread_mutex_unlock(&ctx->lock);

	return root;
}

json_object *rest_api_iat_histograms_json(struct tool_context_s *ctx)
{
	json_object *root = json_object_new_object();
	json_object *streams = json_object_new_array();
	time_t now = time(NULL);

	json_object_object_add(root, "timestampUnix", json_object_new_int64(now));
	json_object_object_add(root, "interface", json_object_new_string(ctx->ifname ? ctx->ifname : ""));
	json_object_object_add(root, "streams", streams);

	pthread_mutex_lock(&ctx->lock);
	struct discovered_item_s *di = NULL;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;

		json_object_array_add(streams, iat_histogram_json(ctx, di));
	}
	pthread_mutex_unlock(&ctx->lock);

	return root;
}

json_object *rest_api_clock_reports_json(struct tool_context_s *ctx)
{
	json_object *root = json_object_new_object();
	json_object *streams = json_object_new_array();
	time_t now = time(NULL);

	json_object_object_add(root, "timestampUnix", json_object_new_int64(now));
	json_object_object_add(root, "interface", json_object_new_string(ctx->ifname ? ctx->ifname : ""));
	json_object_object_add(root, "streams", streams);

	pthread_mutex_lock(&ctx->lock);
	struct discovered_item_s *di = NULL;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;

		json_object_array_add(streams, clock_report_json(di));
	}
	pthread_mutex_unlock(&ctx->lock);

	return root;
}

json_object *rest_api_scte35_json(struct tool_context_s *ctx)
{
	json_object *root = json_object_new_object();
	json_object *streams = json_object_new_array();
	time_t now = time(NULL);

	json_object_object_add(root, "timestampUnix", json_object_new_int64(now));
	json_object_object_add(root, "interface", json_object_new_string(ctx->ifname ? ctx->ifname : ""));
	json_object_object_add(root, "historySeconds", json_object_new_int64(SCTE35_HISTORY_SECONDS));
	json_object_object_add(root, "streams", streams);

	pthread_mutex_lock(&ctx->lock);
	struct discovered_item_s *di = NULL;
	xorg_list_for_each_entry(di, &ctx->list, list) {
		if (discovered_item_state_get(di, DI_STATE_HIDDEN))
			continue;

		json_object_array_add(streams, scte35_json(di, now));
	}
	pthread_mutex_unlock(&ctx->lock);

	return root;
}

static json_object *rest_api_reset_json(struct tool_context_s *ctx)
{
	time(&ctx->lastResetTime);
	discovered_items_stats_reset(ctx);
	if (ctx->procNetUDPContext) {
		ltntstools_proc_net_udp_items_reset_drops(ctx->procNetUDPContext);
	}
	ctx->lastSocketReport = 0;

	json_object *root = json_object_new_object();
	json_object_object_add(root, "status", json_object_new_string("ok"));
	json_object_object_add(root, "message", json_object_new_string("statistics reset"));
	json_object_object_add(root, "resetTimestampUnix", json_object_new_int64(ctx->lastResetTime));
	return root;
}

const char *rest_api_openapi_json(void)
{
	return
		"{\n"
		"  \"openapi\": \"3.0.3\",\n"
		"  \"info\": {\"title\": \"tstools_nic_monitor REST API\", \"version\": \"1.0.0\"},\n"
		"  \"paths\": {\n"
		"    \"/api/transport-streams\": {\"get\": {\"summary\": \"List detected transport streams\", \"responses\": {\"200\": {\"description\": \"Detected streams and summary statistics\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/TransportStreamsResponse\"}}}}}}},\n"
		"    \"/api/transport-pids\": {\"get\": {\"summary\": \"List PID statistics grouped by stream\", \"responses\": {\"200\": {\"description\": \"Per-stream PID statistics\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/TransportPidsResponse\"}}}}}}},\n"
		"    \"/api/stream-models\": {\"get\": {\"summary\": \"List stream service models\", \"responses\": {\"200\": {\"description\": \"PAT/PMT service information grouped by stream\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/StreamModelsResponse\"}}}}}}},\n"
		"    \"/api/stream-logs\": {\"get\": {\"summary\": \"List stream logs\", \"responses\": {\"200\": {\"description\": \"Per-stream log lines\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/StreamLogsResponse\"}}}}}}},\n"
		"    \"/api/iat-histograms\": {\"get\": {\"summary\": \"List IAT histogram reports\", \"responses\": {\"200\": {\"description\": \"Per-stream IAT histogram reports\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/IatHistogramsResponse\"}}}}}}},\n"
		"    \"/api/clock-reports\": {\"get\": {\"summary\": \"List PCR clock reports\", \"responses\": {\"200\": {\"description\": \"Per-stream PCR clock histograms\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/ClockReportsResponse\"}}}}}}},\n"
		"    \"/api/scte35\": {\"get\": {\"summary\": \"List SCTE-35 messages retained in the last three hours\", \"responses\": {\"200\": {\"description\": \"Per-stream SCTE-35 history\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/Scte35Response\"}}}}}}},\n"
		"    \"/api/reset\": {\"post\": {\"summary\": \"Reset collected statistics\", \"responses\": {\"200\": {\"description\": \"Statistics reset acknowledgement\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/ResetResponse\"}}}}}}},\n"
		"    \"/openapi.json\": {\"get\": {\"summary\": \"OpenAPI schema\", \"responses\": {\"200\": {\"description\": \"OpenAPI document\"}}}}\n"
		"  },\n"
		"  \"components\": {\"schemas\": {\n"
		"    \"TransportStreamsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"iatThresholdMs\", \"flagDefinitions\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"iatThresholdMs\": {\"type\": \"integer\"}, \"flagDefinitions\": {\"type\": \"object\", \"additionalProperties\": {\"$ref\": \"#/components/schemas/FlagDefinition\"}}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/TransportStream\"}}}},\n"
		"    \"TransportPidsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/TransportStreamPids\"}}}},\n"
		"    \"StreamModelsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/StreamModel\"}}}},\n"
		"    \"StreamLogsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/StreamLog\"}}}},\n"
		"    \"IatHistogramsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/IatHistogram\"}}}},\n"
		"    \"ClockReportsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/ClockReport\"}}}},\n"
		"    \"Scte35Response\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"historySeconds\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"historySeconds\": {\"type\": \"integer\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/Scte35Stream\"}}}},\n"
		"    \"TransportStream\": {\"type\": \"object\", \"properties\": {\"id\": {\"type\": \"string\"}, \"protocolType\": {\"type\": \"string\"}, \"source\": {\"type\": \"string\"}, \"destination\": {\"type\": \"string\"}, \"firstSeenUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"lastUpdatedUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"bitrateMbps\": {\"type\": \"number\", \"format\": \"double\"}, \"bitrateBps\": {\"type\": \"integer\"}, \"transportPackets\": {\"type\": \"integer\", \"format\": \"int64\"}, \"ccErrors\": {\"type\": \"integer\", \"format\": \"int64\"}, \"iatHighWaterMarkMs\": {\"type\": \"integer\"}, \"iatHighWaterMarkUs\": {\"type\": \"integer\"}, \"flags\": {\"type\": \"string\"}, \"selected\": {\"type\": \"boolean\"}, \"recording\": {\"type\": \"boolean\"}, \"forwarding\": {\"type\": \"boolean\"}, \"srtRetransmissions\": {\"type\": \"integer\", \"format\": \"int64\"}}},\n"
		"    \"FlagDefinition\": {\"type\": \"object\", \"properties\": {\"position\": {\"type\": \"integer\"}, \"symbol\": {\"type\": \"string\"}, \"name\": {\"type\": \"string\"}, \"description\": {\"type\": \"string\"}}},\n"
		"    \"TransportStreamPids\": {\"allOf\": [{\"$ref\": \"#/components/schemas/TransportStreamIdentity\"}, {\"type\": \"object\", \"properties\": {\"pids\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/PidStatistics\"}}}}]},\n"
		"    \"StreamModel\": {\"allOf\": [{\"$ref\": \"#/components/schemas/TransportStreamIdentity\"}, {\"type\": \"object\", \"properties\": {\"available\": {\"type\": \"boolean\"}, \"reason\": {\"type\": \"string\"}, \"multiplexType\": {\"type\": \"string\"}, \"transportStreamId\": {\"type\": \"integer\"}, \"version\": {\"type\": \"integer\"}, \"currentNextIndicator\": {\"type\": \"integer\"}, \"programCount\": {\"type\": \"integer\"}, \"programs\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/ProgramModel\"}}}}]},\n"
		"    \"StreamLog\": {\"allOf\": [{\"$ref\": \"#/components/schemas/TransportStreamIdentity\"}, {\"type\": \"object\", \"properties\": {\"lineCount\": {\"type\": \"integer\"}, \"displayLineFrom\": {\"type\": \"integer\"}, \"pageSize\": {\"type\": \"integer\"}, \"maxPageSize\": {\"type\": \"integer\"}, \"lines\": {\"type\": \"array\", \"items\": {\"type\": \"string\"}}}}]},\n"
		"    \"IatHistogram\": {\"allOf\": [{\"$ref\": \"#/components/schemas/TransportStreamIdentity\"}, {\"type\": \"object\", \"properties\": {\"histogramText\": {\"type\": \"string\"}, \"iatLowWaterMarkUs\": {\"type\": \"integer\"}, \"iatCurrentUs\": {\"type\": \"integer\"}, \"iatHighWaterMarkUs\": {\"type\": \"integer\"}, \"iatHighWaterMarkMs\": {\"type\": \"integer\"}, \"iatHighWaterMarkLastWindowUs\": {\"type\": \"integer\"}, \"iatHighWaterMarkLastWindowMs\": {\"type\": \"integer\"}, \"bitrateHighWaterMark10msBps\": {\"type\": \"integer\"}, \"bitrateHighWaterMark100msBps\": {\"type\": \"integer\"}, \"bitrateHighWaterMark10msMbps\": {\"type\": \"number\"}, \"bitrateHighWaterMark100msMbps\": {\"type\": \"number\"}, \"microburstMeasurementEnabled\": {\"type\": \"boolean\"}}}}]},\n"
		"    \"ClockReport\": {\"allOf\": [{\"$ref\": \"#/components/schemas/TransportStreamIdentity\"}, {\"type\": \"object\", \"properties\": {\"available\": {\"type\": \"boolean\"}, \"reason\": {\"type\": \"string\"}, \"pcrPids\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/PcrClockPid\"}}}}]},\n"
		"    \"PcrClockPid\": {\"type\": \"object\", \"properties\": {\"pid\": {\"type\": \"integer\"}, \"pidHex\": {\"type\": \"string\"}, \"pcr\": {\"type\": \"integer\", \"format\": \"int64\"}, \"pcrAscii\": {\"type\": \"string\"}, \"pcrTickIntervalsText\": {\"type\": \"string\"}, \"pcrWallDriftText\": {\"type\": \"string\"}}},\n"
		"    \"Scte35Stream\": {\"allOf\": [{\"$ref\": \"#/components/schemas/TransportStreamIdentity\"}, {\"type\": \"object\", \"properties\": {\"historySeconds\": {\"type\": \"integer\"}, \"pidCount\": {\"type\": \"integer\"}, \"messageCount\": {\"type\": \"integer\"}, \"pids\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/Scte35Pid\"}}, \"messages\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/Scte35Message\"}}}}]},\n"
		"    \"Scte35Pid\": {\"type\": \"object\", \"properties\": {\"pid\": {\"type\": \"integer\"}, \"pidHex\": {\"type\": \"string\"}, \"videoPid\": {\"type\": \"integer\"}, \"videoPidHex\": {\"type\": \"string\"}, \"messageCount\": {\"type\": \"integer\", \"format\": \"int64\"}, \"lastVideoPTS\": {\"type\": \"integer\", \"format\": \"int64\"}}},\n"
		"    \"Scte35Message\": {\"type\": \"object\", \"properties\": {\"sequenceNumber\": {\"type\": \"integer\", \"format\": \"int64\"}, \"receivedAtUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"ageSeconds\": {\"type\": \"integer\"}, \"pid\": {\"type\": \"integer\"}, \"pidHex\": {\"type\": \"string\"}, \"videoPid\": {\"type\": \"integer\"}, \"videoPidHex\": {\"type\": \"string\"}, \"videoPTS\": {\"type\": \"integer\", \"format\": \"int64\"}, \"crcValid\": {\"type\": \"boolean\"}, \"parseOk\": {\"type\": \"boolean\"}, \"sectionLengthBytes\": {\"type\": \"integer\"}, \"rawSectionHex\": {\"type\": \"string\"}, \"decoded\": {\"type\": \"object\"}, \"decodedText\": {\"type\": \"string\"}}},\n"
		"    \"ProgramModel\": {\"type\": \"object\", \"properties\": {\"programNumber\": {\"type\": \"integer\"}, \"pmtPid\": {\"type\": \"integer\"}, \"pmtPidHex\": {\"type\": \"string\"}, \"pcrPid\": {\"type\": \"integer\"}, \"pcrPidHex\": {\"type\": \"string\"}, \"streamCount\": {\"type\": \"integer\"}, \"serviceName\": {\"type\": \"string\"}, \"serviceProvider\": {\"type\": \"string\"}, \"hasScte35Registration\": {\"type\": \"boolean\"}, \"hasSmpte2038Registration\": {\"type\": \"boolean\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/ElementaryStreamModel\"}}}},\n"
		"    \"ElementaryStreamModel\": {\"type\": \"object\", \"properties\": {\"pid\": {\"type\": \"integer\"}, \"pidHex\": {\"type\": \"string\"}, \"streamType\": {\"type\": \"integer\"}, \"streamTypeHex\": {\"type\": \"string\"}, \"description\": {\"type\": \"string\"}}},\n"
		"    \"TransportStreamIdentity\": {\"type\": \"object\", \"properties\": {\"id\": {\"type\": \"string\"}, \"protocolType\": {\"type\": \"string\"}, \"source\": {\"type\": \"string\"}, \"destination\": {\"type\": \"string\"}, \"firstSeenUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"lastUpdatedUnix\": {\"type\": \"integer\", \"format\": \"int64\"}}},\n"
		"    \"PidStatistics\": {\"type\": \"object\", \"properties\": {\"pid\": {\"type\": \"integer\", \"minimum\": 0, \"maximum\": 8191}, \"pidHex\": {\"type\": \"string\"}, \"bitrateMbps\": {\"type\": \"number\", \"format\": \"double\"}, \"transportPackets\": {\"type\": \"integer\", \"format\": \"int64\"}, \"ccErrors\": {\"type\": \"integer\", \"format\": \"int64\"}, \"teiErrors\": {\"type\": \"integer\", \"format\": \"int64\"}}},\n"
		"    \"ResetResponse\": {\"type\": \"object\", \"properties\": {\"status\": {\"type\": \"string\", \"enum\": [\"ok\"]}, \"message\": {\"type\": \"string\"}, \"resetTimestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}}}\n"
		"  }}\n"
		"}\n";
}

static void http_reply(int fd, int status, const char *status_text, const char *content_type, const char *body)
{
	size_t body_len = strlen(body);
	dprintf(fd,
		"HTTP/1.1 %d %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n",
		status, status_text, content_type, body_len);
	write(fd, body, body_len);
}

static void http_json_reply(int fd, json_object *obj)
{
	const char *body = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
	http_reply(fd, 200, "OK", "application/json", body);
}

static void service_client(struct tool_context_s *ctx, int fd)
{
	char req[2048];
	ssize_t r = read(fd, req, sizeof(req) - 1);
	if (r <= 0)
		return;
	req[r] = 0;

	char method[16] = { 0 };
	char path[512] = { 0 };
	if (sscanf(req, "%15s %511s", method, path) != 2) {
		http_reply(fd, 400, "Bad Request", "application/json", "{\"error\":\"bad request\"}\n");
		return;
	}
	char *query = strchr(path, '?');
	if (query)
		*query = 0;

	if (strcmp(path, "/api/transport-streams") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_transport_streams_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/api/transport-pids") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_transport_pids_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/api/stream-models") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_stream_models_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/api/stream-logs") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_stream_logs_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/api/iat-histograms") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_iat_histograms_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/api/clock-reports") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_clock_reports_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/api/scte35") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_scte35_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/api/reset") == 0) {
		if (strcmp(method, "POST") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		json_object *obj = rest_api_reset_json(ctx);
		http_json_reply(fd, obj);
		json_object_put(obj);
	} else if (strcmp(path, "/openapi.json") == 0) {
		if (strcmp(method, "GET") != 0) {
			http_reply(fd, 405, "Method Not Allowed", "application/json", "{\"error\":\"method not allowed\"}\n");
			return;
		}
		http_reply(fd, 200, "OK", "application/json", rest_api_openapi_json());
	} else {
		http_reply(fd, 404, "Not Found", "application/json", "{\"error\":\"not found\"}\n");
	}
}

int rest_api_initialize(struct tool_context_s *ctx)
{
	if (ctx->rest_api_port <= 0)
		return 0;

	ctx->rest_api_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (ctx->rest_api_socket < 0)
		return -1;

	int on = 1;
	setsockopt(ctx->rest_api_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(ctx->rest_api_port);

	if (bind(ctx->rest_api_socket, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(ctx->rest_api_socket);
		ctx->rest_api_socket = -1;
		return -1;
	}
	if (listen(ctx->rest_api_socket, 16) < 0) {
		close(ctx->rest_api_socket);
		ctx->rest_api_socket = -1;
		return -1;
	}

	return 0;
}

void rest_api_free(struct tool_context_s *ctx)
{
	if (ctx->rest_api_socket >= 0) {
		close(ctx->rest_api_socket);
		ctx->rest_api_socket = -1;
	}
}

void *rest_api_thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->rest_api_threadRunning = 1;
	ctx->rest_api_threadTerminate = 0;
	ctx->rest_api_threadTerminated = 0;

	ltnpthread_setname_np(ctx->rest_api_threadId, "tstools-rest");
	pthread_detach(pthread_self());

	while (!ctx->rest_api_threadTerminate) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(ctx->rest_api_socket, &rfds);

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 100 * 1000;

		int sr = select(ctx->rest_api_socket + 1, &rfds, NULL, NULL, &tv);
		if (sr <= 0)
			continue;

		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int fd = accept(ctx->rest_api_socket, (struct sockaddr *)&addr, &addrlen);
		if (fd < 0) {
			if (errno == EINTR)
				continue;
			if (ctx->rest_api_threadTerminate)
				break;
			usleep(50 * 1000);
			continue;
		}

		service_client(ctx, fd);
		close(fd);
	}

	ctx->rest_api_threadTerminated = 1;
	pthread_exit(NULL);
	return NULL;
}
