/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"

int64_t output_get_computed_stc(struct tool_ctx_s *ctx)
{
	double startupPacketsSent = 10000;
	double bitsTransmitted = (startupPacketsSent + ctx->ts_packets_sent) * TS_PACKET_SIZE * 8.0;
	double additionalBits = 0.0;
	double bps = TARGET_BITRATE;

	return (((bitsTransmitted + additionalBits) / bps) * (double)27000000);
}

int output_write(struct output_stream_s *os, const uint8_t *pkts, int packetCount)
{
	ltntstools_pid_stats_update(os->libstats, pkts, packetCount);
	avio_write(os->avio_ctx, pkts, packetCount * 188);

	return packetCount;
}

static void *reframer_callback(struct output_stream_s *os, const uint8_t *buf, int lengthBytes)
{
	output_write(os, buf, lengthBytes / 188);
	return NULL;
}

struct output_stream_s *output_stream_alloc(struct tool_ctx_s *ctx)
{
	struct output_stream_s *os = calloc(1, sizeof(*os));
	if (!os)
		return NULL;

	os->ctx = ctx;
	os->reframer = ltntstools_reframer_alloc(os, 7 * 188, (ltntstools_reframer_callback)reframer_callback);

	os->oname = strdup("udp://227.1.131.201:4001");

	int ret = avio_open2(&os->avio_ctx, os->oname, AVIO_FLAG_WRITE | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-o syntax error\n");
		exit(1);
	}

	ltntstools_pid_stats_alloc(&os->libstats);

	double bitrate_bps = TARGET_BITRATE;
	double packet_duration_sec = (double)(188.0 * 8.0) / bitrate_bps;
	double ticks_per_packet = packet_duration_sec * 27000000.0;
	os->ticks_per_outputts27MHz = ticks_per_packet;

	/* Mostly hardcoded. Buld a PAT object and we'll synthesize actial PAT/PMT packets from this. */
	os->pat = ltntstools_pat_alloc();
	struct ltntstools_pat_s *pat = os->pat;
	pat->transport_stream_id = 1;
	pat->version_number = 1;
	pat->current_next_indicator = 1;
	pat->program_count = 2;

	/* construct a new PMT */
	// for (int i = 0; i <= ctx->inputNr; i++) {
	for (int i = 0; i < 1; i++) {
		int prog = i + 1;
		pat->programs[i].program_number = prog;
		pat->programs[i].program_map_PID = 0x100 * prog;
		pat->programs[i].pmt.current_next_indicator = 1;
		pat->programs[i].pmt.PCR_PID = 0x31 + (0x100 * prog);
		pat->programs[i].pmt.program_number = prog;
		pat->programs[i].pmt.version_number = 1;
		pat->programs[i].pmt.stream_count = 2;
		pat->programs[i].pmt.streams[0].elementary_PID = 0x31 + (0x100 * prog);
		pat->programs[i].pmt.streams[0].stream_type    = 0x1b;
		pat->programs[i].pmt.streams[1].elementary_PID = 0x32 + (0x100 * prog);
		pat->programs[i].pmt.streams[1].stream_type    = 0x04;
		//pat->programs[i].pmt.streams[1].stream_type    = 0x81; // AC3
	}

	return os;
}

void output_stream_free(struct output_stream_s *os)
{
	//struct tool_ctx_s *ctx = os->ctx;

	if (os->pat) {
		ltntstools_pat_free(os->pat);
		os->pat = NULL;
	}

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

}
