/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

#include "hexdump.h"
#include "dump.h"

#define VIDEO_STREAM_DR		0xF2
#define CA_DR			0x09
#define SYSTEM_CLOCK_DR		0x0B
#define MAX_BITRATE_DR		0x0E
#define STREAM_IDENTIFIER_DR	0x52
#define SUBTITLING_DR		0x59

#define MAX_PIDS 8192

struct ts_stream_s;

enum ts_pid_psiptype_e
{
	PID_UNKNOWN = 0,
	PID_PAT,
	PID_PCR,
	PID_CA,
	PID_PMT
};

struct ts_pid_s
{
	struct ts_stream_s *strm;
	unsigned int		    used;
	uint16_t		        pid;
	dvbpsi_t		       *dvbpsi;
	enum ts_pid_psiptype_e	psip_type;
};

struct ts_stream_s {
	struct ts_pid_s		*pids;
	void			        *userctx;
  int                totalPMTS;
  int                countPMTS;
};

void destroyPID(struct ts_pid_s *pid);
void freeStream(struct ts_stream_s *strm);
int  allocStream(struct ts_stream_s **strm, void *userctx);
__inline__ struct ts_pid_s *findPID(struct ts_stream_s *strm, uint16_t pid);
void updateStream(struct ts_stream_s *strm, unsigned char *buf, unsigned int len);

__inline__ struct ts_pid_s *findPID(struct ts_stream_s *strm, uint16_t pid)
{
	assert(pid < MAX_PIDS);
	return &strm->pids[pid];
}

void freeStream(struct ts_stream_s *strm)
{
	struct ts_pid_s *p;

	for (int i = 0; i < MAX_PIDS; i++) {
		p = findPID(strm, i);
		destroyPID(p);
	}

	memset(strm, 0, sizeof(*strm));
	free(strm);
}

int allocStream(struct ts_stream_s **stream, void *userctx)
{
	/* Allocate the primary object ... */
	struct ts_stream_s *strm = calloc(1, sizeof(struct ts_stream_s));
	if (strm == 0)
		return -1;

	/* Any context informatioon we need to cache */
	strm->userctx = userctx;

	/* Allocate the pids struct ... */
	strm->pids = calloc(MAX_PIDS, sizeof(struct ts_pid_s));
	if (strm->pids == 0) {
		free(strm);
		return -1;
	}

	for (int i = 0; i < MAX_PIDS; i++) {
		struct ts_pid_s *p = findPID(strm, i);
		p->pid = i;
		p->used = 0;
		p->psip_type = PID_UNKNOWN;
		p->strm = strm;
	}

	*stream = strm;

	return 0;
}

void destroyPID(struct ts_pid_s *pid)
{
	if (pid->used == 0)
		return;

	if (pid->dvbpsi == 0)
		return;

	switch (pid->psip_type) {
	case PID_PAT:
		dvbpsi_pat_detach(pid->dvbpsi);
		break;
	case PID_PMT:
		dvbpsi_pmt_detach(pid->dvbpsi);
		break;
	default:
		printf("psip_type = %d\n", pid->psip_type);
		assert(0);
	}

	dvbpsi_delete(pid->dvbpsi);
	pid->dvbpsi = 0;
	pid->used = 0;
	pid->psip_type = PID_UNKNOWN;
}

void updateStream(struct ts_stream_s *strm, unsigned char *buf, unsigned int len)
{
	struct ts_pid_s *pid;
	unsigned int i;
	uint16_t i_pid;

	for (i = 0; i < len; i += 188) {
		i_pid = ((uint16_t)(*(buf + 1) & 0x1f) << 8) | *(buf + 2);
		pid = findPID(strm, i_pid);
		if (pid->used)
			dvbpsi_packet_push(pid->dvbpsi, buf + i);
	}
}

static void completionPMT(void* p_zero, dvbpsi_pmt_t* p_pmt)
{
	struct ts_pid_s *pid = p_zero;
	struct ts_stream_s *strm = pid->strm;
  strm->countPMTS++;

  tstools_DumpPMT(p_zero, p_pmt);

	//dvbpsi_pmt_es_t* p_es = p_pmt->p_first_es;

	dvbpsi_pmt_delete(p_pmt);
}

static void completionPAT(void *p_zero, dvbpsi_pat_t *p_pat)
{
	struct ts_stream_s *strm = p_zero;
	struct ts_pid_s *pid;

  tstools_DumpPAT(p_zero, p_pat);

	dvbpsi_pat_program_t *p_program = p_pat->p_first_program;
	while (p_program) {
		pid = findPID(strm, p_program->i_pid);

    strm->totalPMTS++;
		pid->dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_NONE);
		if (pid->dvbpsi == NULL) {
			printf("Huh?\n");
			assert(0);
		}

		dvbpsi_pmt_attach(pid->dvbpsi, p_program->i_number, completionPMT, pid);
		pid->used = 1;
		pid->psip_type = PID_PMT;

		p_program = p_program->p_next;
	}

	dvbpsi_pat_delete(p_pat);
}

int si_inspector(int i_argc, char* pa_argv[])
{
	struct ts_stream_s *strm;
	struct ts_pid_s *pat;

	uint8_t data[188];
	int i_fd;
	bool b_ok;

	if (i_argc != 2)
		return 1;

	if (allocStream(&strm, NULL) < 0)
		return 1;

	i_fd = open(pa_argv[1], 0);
	if (i_fd < 0)
		return 1;

	pat = findPID(strm, 0);
	pat->dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_NONE);
	if (pat->dvbpsi == NULL)
		goto out;

	if (!dvbpsi_pat_attach(pat->dvbpsi, completionPAT, strm))
		goto out;
	pat->used = 1;
	pat->psip_type = PID_PAT;

	b_ok = tstools_ReadPacket(i_fd, data);
	while (b_ok) {
		updateStream(strm, data, 188);
		b_ok = tstools_ReadPacket(i_fd, data);

    if (strm->totalPMTS > 0 && (strm->countPMTS == strm->totalPMTS))
      break;
	}

out:
	close(i_fd);

	freeStream(strm);

	return 0;
}


