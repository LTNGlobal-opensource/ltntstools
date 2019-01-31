/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#ifndef _PIDS_H
#define _PIDS_H

#include <time.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define getPID(pkt) (((*((pkt) + 1) << 8) | *((pkt) + 2)) & 0x1fff)
#define getCC(pkt) (*((pkt) + 3) & 0x0f)
#define getPacketAdaption(pkt) ((*((pkt) + 3) & 0x30) >> 4)
#define getScrambled(pkt) ((*((pkt) + 3) & 0xc0) >> 6)
#define isTEI(pkt) ((*((pkt) + 1) & 0x80) ? 1 : 0)
#define isPayloadStartIndicator(pkt) (*((pkt) + 1) & 0x40 ? 1 : 0)

#define MAX_PID 8192
struct pid_statistics_s
{
	int enabled;
	uint64_t packetCount;
	uint64_t ccErrors;
	uint64_t teiErrors;

	uint8_t lastCC;

	/* Maintain a packets per second count, we can convert this into Mb/ps */
	time_t pps_last_update;
	uint32_t pps;
	uint32_t pps_window;
	double mbps; /* Updated once per second. */
};

struct stream_statistics_s
{
	struct pid_statistics_s pids[MAX_PID];
	uint64_t packetCount;
	uint64_t teiErrors;
	uint64_t ccErrors;

	/* Maintain a packets per second count, we can convert this into Mb/ps */
	time_t pps_last_update;
	uint32_t pps;
	uint32_t pps_window;
	double mbps; /* Updated once per second. */
};

int isCCInError(const uint8_t *pkt, uint8_t oldCC);
void pid_stats_update(struct stream_statistics_s *stream, const uint8_t *pkts, uint32_t packetCount);
void pid_stats_reset(struct stream_statistics_s *stream);

#ifdef __cplusplus
};
#endif

#endif /* _PIDS_H */
