/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include "pids.h"

int isCCInError(const uint8_t *pkt, uint8_t oldCC)
{
	unsigned int adap = getPacketAdaption(pkt);
	unsigned int cc = getCC(pkt);

	if (((adap == 0) || (adap == 2)) && (oldCC == cc))
		return 0;

	if (((adap == 1) || (adap == 3)) && (oldCC == cc))
		return 1;

	if (((oldCC + 1) & 0x0f) == cc)
		return 0;

	return 1;
}

void pid_stats_update(struct stream_statistics_s *stream, const uint8_t *pkts, uint32_t packetCount)
{
	time_t now;
	time(&now);

	for (int i = 0; i < packetCount; i++) {
		int offset = i * 188;
		if (*(pkts + offset) == 0x47)
			stream->packetCount++;
		else
			stream->ccErrors++;
	}

	if (now != stream->pps_last_update) {
		stream->pps = stream->pps_window;
		stream->pps_window = 0;
		stream->mbps = stream->pps;
		stream->mbps *= (188 * 8);
		stream->mbps /= 1e6;
		stream->pps_last_update = now;
	}
	stream->pps_window += packetCount;

	for (int i = 0; i < packetCount; i++) {
		int offset = i * 188;

		uint16_t pidnr = getPID(pkts + offset);
		struct pid_statistics_s *pid = &stream->pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		if (now != pid->pps_last_update) {
			pid->pps = pid->pps_window;
			pid->pps_window = 0;
			pid->mbps = pid->pps;
			pid->mbps *= (188 * 8);
			pid->mbps /= 1e6;
			pid->pps_last_update = now;
		}
		pid->pps_window++;

		uint8_t cc = getCC(pkts + offset);
		if (isCCInError(pkts + offset, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
				pid->ccErrors++;
				stream->ccErrors++;
			}
		}

		pid->lastCC = cc;

		if (isTEI(pkts + offset)) {
			pid->teiErrors++;
			stream->teiErrors++;
		}
	}
}
