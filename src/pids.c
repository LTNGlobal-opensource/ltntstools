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

void pid_stats_reset(struct stream_statistics_s *stream)
{
	stream->packetCount = 0;
	stream->teiErrors = 0;
	stream->ccErrors = 0;
	stream->mbps = 0;

	for (int i = 0; i < MAX_PID; i++) {
		if (!stream->pids[i].enabled)
			continue;
		stream->pids[i].packetCount = 0;
		stream->pids[i].ccErrors = 0;
		stream->pids[i].teiErrors = 0;
		stream->pids[i].mbps = 0;
	}
}

static void _expire_per_second_stream_stats(struct stream_statistics_s *stream)
{
	time_t now;
	time(&now);

	if (now > stream->pps_last_update + 2) {
		stream->mbps = 0;
		stream->pps = 0;
		stream->pps_window = 0;
	}
}

double pid_stats_stream_get_mbps(struct stream_statistics_s *stream)
{
	_expire_per_second_stream_stats(stream);
	return stream->mbps;
}

uint32_t pid_stats_stream_get_pps(struct stream_statistics_s *stream)
{
	_expire_per_second_stream_stats(stream);
	return stream->pps;
}

uint32_t pid_stats_stream_get_bps(struct stream_statistics_s *stream)
{
	_expire_per_second_stream_stats(stream);
	return stream->pps * 188 * 8;
}

static void _expire_per_second_pid_stats(struct pid_statistics_s *pid)
{
	time_t now;
	time(&now);

	if (now > pid->pps_last_update + 2) {
		pid->mbps = 0;
		pid->pps = 0;
		pid->pps_window = 0;
	}
}

double pid_stats_pid_get_mbps(struct stream_statistics_s *stream, uint16_t pidnr)
{
	struct pid_statistics_s *pid = &stream->pids[pidnr & 0x1fff];
	_expire_per_second_pid_stats(pid);
	return pid->mbps;
}

uint32_t pid_stats_pid_get_pps(struct stream_statistics_s *stream, uint16_t pidnr)
{
	struct pid_statistics_s *pid = &stream->pids[pidnr & 0x1fff];
	_expire_per_second_pid_stats(pid);
	return pid->pps;
}

uint32_t pid_stats_pid_get_bps(struct stream_statistics_s *stream, uint16_t pidnr)
{
	struct pid_statistics_s *pid = &stream->pids[pidnr & 0x1fff];
	_expire_per_second_pid_stats(pid);
	return pid->pps * 188 * 8;
}

