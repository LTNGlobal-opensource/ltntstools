/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"

int output_computed_stc_established(struct output_stream_s *os)
{
	return os->stc_established;
}

void output_set_computed_stc(struct output_stream_s *os, int64_t PTS)
{
	/* Convert PTS into meaningful STC. */
	double stc = (PTS * 300);
	double bps = TARGET_BITRATE;
	double bitsTransmitted = (stc / 27000) * (bps / 1000);
	double ts_packet_sent = bitsTransmitted / 8 / 188;

	os->ts_packets_sent = ts_packet_sent;
	os->stc_established = 1;
}

int64_t output_get_computed_stc(struct output_stream_s *os)
{
	if (!os->stc_established) {
		printf("how does this happen?\n");
		//exit(1);
		return 0;
	}

	double bitsTransmitted = os->ts_packets_sent * 188 * 8.0;
	double bps = TARGET_BITRATE;

	return (bitsTransmitted / bps) * (double)27000000;
}

static void *reframer_callback(struct output_stream_s *os, const uint8_t *buf, int lengthBytes)
{
	/* The reframe hands us 7*188 buffers os TS packets... update the TS stats... */
	ltntstools_pid_stats_update(os->libstats, buf, lengthBytes / 188);

#if TS_RECORDING
	static FILE *ofh = NULL;
	if (ofh == NULL)
		ofh = fopen("output.ts", "wb");
	if (ofh)
		fwrite(buf, 1, lengthBytes, ofh);
#endif

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
	os->stc_established = 0;
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

	ltntstools_generateNullPacket(&os->null_pkt[0]);

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
