/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#ifndef _PIDS_H
#define _PIDS_H

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
};

struct stream_statistics_s
{
	struct pid_statistics_s pids[MAX_PID];
};

__inline__ int isCCInError(uint8_t *pkt, uint8_t oldCC)
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

#ifdef __cplusplus
};
#endif

#endif /* _PIDS_H */
