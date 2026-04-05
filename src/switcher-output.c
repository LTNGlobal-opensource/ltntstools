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

void *output_reframer_callback(struct output_stream_s *os, const uint8_t *buf, int lengthBytes)
{
	sendto(os->sockfd, buf, lengthBytes, 0, (struct sockaddr *)&os->addr, sizeof(os->addr));
	return NULL;
}

int output_alloc(struct tool_ctx_s *ctx, struct output_stream_s **outputStream)
{
	struct output_stream_s *os = calloc(1, sizeof(*os));
	if (!os) {
		return -1;
	}

	os->ctx = ctx;

	/* Mostly hardcoded. Buld a PAT object and we'll synthesize actial PAT/PMT packets from this. */
	os->pat = ltntstools_pat_alloc();

	struct ltntstools_pat_s *pat = os->pat;
	int prog = 1;
	int i = 0;
	pat->transport_stream_id = 1;
	pat->version_number = 1;
	pat->current_next_indicator = 1;
	pat->program_count = 1;
	pat->programs[i].program_number = prog;
	pat->programs[i].program_map_PID = 0x100 * prog;
	pat->programs[i].pmt.current_next_indicator = 1;
	pat->programs[i].pmt.PCR_PID = 0x31 + (0x100 * prog);
	pat->programs[i].pmt.program_number = prog;
	pat->programs[i].pmt.version_number = 1;
	pat->programs[i].pmt.stream_count = 2;
	pat->programs[i].pmt.streams[0].elementary_PID = 0x31 + (0x100 * prog); /* AVC Video */
	pat->programs[i].pmt.streams[0].stream_type    = 0x1b;
	pat->programs[i].pmt.streams[1].elementary_PID = 0x32 + (0x100 * prog); /* Mp2 Audio */
	pat->programs[i].pmt.streams[1].stream_type    = 0x04;
//	pat->programs[i].pmt.streams[1].stream_type    = 0x81; // AC3

	os->reframer = ltntstools_reframer_alloc(ctx, 7 * 188, (ltntstools_reframer_callback)output_reframer_callback);

	/* Setup UDP socket for output */
    os->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	os->addr.sin_family = AF_INET;
    os->addr.sin_port = htons(4900);
    inet_pton(AF_INET, "227.1.20.45", &os->addr.sin_addr);

	/* For the entire output mux, determine the number of ticks per TS packet */
	double bitrate_bps = TARGET_BITRATE;
	double packet_duration_sec = (double)(188.0 * 8.0) / bitrate_bps;
	double ticks_per_packet = packet_duration_sec * 27000000.0;
	os->ticks_per_outputts27MHz = ticks_per_packet;

	*outputStream = os;

	return 0;
}

void output_free(struct output_stream_s *os)
{
	ltntstools_pat_free(os->pat);
	ltntstools_reframer_free(os->reframer);
	close(os->sockfd);
}

int output_write(struct output_stream_s *os, uint8_t *pkt, int byteCount)
{
	ltststools_reframer_write(os->reframer, pkt, byteCount);
	os->ts_packets_sent++;

	return byteCount;
}

void output_generate_psip(struct output_stream_s *os)
{
	struct tool_ctx_s *ctx = os->ctx;

	/* Generate the PSIP multiple times a second, and schedule them for output. */
	os->last_psip = ctx->next_time;

	ctx->output_psip_idx = 0; /* Throw a flag, start outputting the PSIO from packet 0 */
	ltntstools_pat_create_packet_ts(os->pat, os->psip_cc[0]++, &os->psip_pkt[0][0], 188);
	ltntstools_pmt_create_packet_ts(&os->pat->programs[0].pmt, os->pat->programs[0].program_map_PID, os->psip_cc[1]++, &os->psip_pkt[1][0], 188);
	ltntstools_pmt_create_packet_ts(&os->pat->programs[1].pmt, os->pat->programs[1].program_map_PID, os->psip_cc[2]++, &os->psip_pkt[2][0], 188);
}