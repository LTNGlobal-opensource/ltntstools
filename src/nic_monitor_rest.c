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

json_object *rest_api_transport_streams_json(struct tool_context_s *ctx)
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
		"    \"/api/reset\": {\"post\": {\"summary\": \"Reset collected statistics\", \"responses\": {\"200\": {\"description\": \"Statistics reset acknowledgement\", \"content\": {\"application/json\": {\"schema\": {\"$ref\": \"#/components/schemas/ResetResponse\"}}}}}}},\n"
		"    \"/openapi.json\": {\"get\": {\"summary\": \"OpenAPI schema\", \"responses\": {\"200\": {\"description\": \"OpenAPI document\"}}}}\n"
		"  },\n"
		"  \"components\": {\"schemas\": {\n"
		"    \"TransportStreamsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/TransportStream\"}}}},\n"
		"    \"TransportPidsResponse\": {\"type\": \"object\", \"required\": [\"timestampUnix\", \"interface\", \"streams\"], \"properties\": {\"timestampUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"interface\": {\"type\": \"string\"}, \"streams\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/TransportStreamPids\"}}}},\n"
		"    \"TransportStream\": {\"type\": \"object\", \"properties\": {\"id\": {\"type\": \"string\"}, \"protocolType\": {\"type\": \"string\"}, \"source\": {\"type\": \"string\"}, \"destination\": {\"type\": \"string\"}, \"firstSeenUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"lastUpdatedUnix\": {\"type\": \"integer\", \"format\": \"int64\"}, \"bitrateMbps\": {\"type\": \"number\", \"format\": \"double\"}, \"bitrateBps\": {\"type\": \"integer\"}, \"transportPackets\": {\"type\": \"integer\", \"format\": \"int64\"}, \"ccErrors\": {\"type\": \"integer\", \"format\": \"int64\"}, \"iatHighWaterMarkMs\": {\"type\": \"integer\"}, \"iatHighWaterMarkUs\": {\"type\": \"integer\"}, \"flags\": {\"type\": \"string\"}, \"selected\": {\"type\": \"boolean\"}, \"recording\": {\"type\": \"boolean\"}, \"forwarding\": {\"type\": \"boolean\"}, \"srtRetransmissions\": {\"type\": \"integer\", \"format\": \"int64\"}}},\n"
		"    \"TransportStreamPids\": {\"allOf\": [{\"$ref\": \"#/components/schemas/TransportStreamIdentity\"}, {\"type\": \"object\", \"properties\": {\"pids\": {\"type\": \"array\", \"items\": {\"$ref\": \"#/components/schemas/PidStatistics\"}}}}]},\n"
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
