/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"

int64_t output_get_computed_stc(struct output_stream_s *os)
{
	double startupPacketsSent = 10000;
	double bitsTransmitted = (startupPacketsSent + os->ts_packets_sent) * TS_PACKET_SIZE * 8.0;
	double additionalBits = 0.0;
	double bps = TARGET_BITRATE;

	return (((bitsTransmitted + additionalBits) / bps) * (double)27000000);
}

static void *reframer_callback(struct output_stream_s *os, const uint8_t *buf, int lengthBytes)
{
	/* The reframe hands us 7*188 buffers os TS packets... update the TS stats... */
	ltntstools_pid_stats_update(os->libstats, buf, lengthBytes / 188);

	/* And write the packets to the network */
	avio_write(os->avio_ctx, buf, lengthBytes);

	return NULL;
}

struct output_stream_s *output_stream_alloc(struct tool_ctx_s *ctx)
{
	struct output_stream_s *os = calloc(1, sizeof(*os));
	if (!os)
		return NULL;

	os->ctx = ctx;
	os->reframer = ltntstools_reframer_alloc(os, 7 * 188, (ltntstools_reframer_callback)reframer_callback);
	if (os->reframer == NULL) {
		free(os);
		return NULL;
	}

#if 0
	os->oname = strdup("udp://227.1.131.201:4001");
#else
	os->oname = strdup("udp://227.1.131.51:4051?pkt_size=1316"); /* ltnt-col-videolab-e3 */
#endif

	int ret = avio_open2(&os->avio_ctx, os->oname, AVIO_FLAG_WRITE | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-o syntax error\n");
		exit(1);
	}

	ltntstools_pid_stats_alloc(&os->libstats);
	if (os->libstats == NULL) {
		ltntstools_reframer_free(os->reframer);
		free(os);
		return NULL;
	}

	double bitrate_bps = TARGET_BITRATE;
	double packet_duration_sec = (double)(188.0 * 8.0) / bitrate_bps;
	double ticks_per_packet = packet_duration_sec * 27000000.0;
	os->ticks_per_outputts27MHz = ticks_per_packet;

	return os;
}

void output_stream_free(struct output_stream_s *os)
{
	//struct tool_ctx_s *ctx = os->ctx;

	if (os->reframer) {
		ltntstools_reframer_free(os->reframer);
		os->reframer = NULL;
	}

	if (os->libstats) {
		ltntstools_pid_stats_free(os->libstats);
		os->libstats = NULL;
	}

	if (os->avio_ctx) {
		avio_close(os->avio_ctx);
		os->avio_ctx = NULL;
	}

	if (os->oname) {
		free(os->oname);
		os->oname = NULL;
	}

	free(os);
}
