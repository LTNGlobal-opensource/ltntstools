/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"


static const char *pidTypeNames[] = {
	"PID_UNDEFINED",
	"PID_VIDEO",
	"PID_AUDIO",
	"PID_OTHER",
};

const char *getPidTypeDescription(enum pid_type_e type)
{
	return pidTypeNames[type]; 
}

static void *input_stream_pid_vbv_callback(void *userContext, enum ltntstools_vbv_event_e event)
{
	struct pid_s *pid = (struct pid_s *)userContext;
	struct input_stream_s *is = pid->stream;

	struct timeval now;
	gettimeofday(&now, NULL);

#if 0

/* TODO: Disabled */
	tprintf("stream[%d] pid 0x%04x (%04d) %s\n",
		is->nr,
		pid->outputPidNr, pid->outputPidNr,
		ltntstools_vbv_event_name(event));
#endif

	return NULL;
}

static void *input_stream_pid_pe_callback(struct pid_s *pid, struct ltn_pes_packet_s *pes)
{
	struct input_stream_s *stream = pid->stream;
	struct output_stream_s *os = stream->ctx->outputStream;

	if (!output_computed_stc_established(os)) {
		if (ltn_pes_packet_has_PTS(pes)) {
			output_set_computed_stc(os, pes->PTS);
		}
	}
#if 0
	if (!ltn_pes_packet_has_DTS(pes)) {
		pes->DTS = pes->PTS;
	}
#endif

	if (stream->ctx->verbose && pid->pid == 0x101 && stream->nr == 0) {
		tprintf("pes->pid 0x%02x pts %14" PRIi64 " dts %14" PRIi64 " pcr %14" PRIi64 ", length %d\n", pid->outputPidNr, pes->PTS, pes->DTS, pes->pcr, pes->dataLengthBytes);
	}
#if 0
	if (pid->vbv && pid->type == PID_VIDEO && ltntstools_vbv_write(pid->vbv, (const struct ltn_pes_packet_s *)pes) < 0) {
		fprintf(stderr, "Error writing PES to VBV\n");
	}
#endif
	struct pes_item_s *item = pes_item_alloc(pid, pes, os);
	if (item) {

		/* Cache the pes, payload and other things. We're re-packetize them later. */
		pthread_mutex_lock(&pid->peslistlock);
		xorg_list_append(&item->list, &pid->peslist);
		pid->peslistcount++;
		pthread_mutex_unlock(&pid->peslistlock);

		// pes_item_dump(item, 1);

		/* Cache the timing specific context - We're reference this when regenerating timing */
		struct timing_item_s *ti = timing_item_alloc(item); 
		pthread_mutex_lock(&pid->tilistlock);
		xorg_list_append(&ti->list, &pid->tilist); 
		pthread_mutex_unlock(&pid->tilistlock);

	} else {
		//ltn_pes_packet_dump(pes, "");
		ltn_pes_packet_free(pes);
	}
#if 0
	if (stream->ctx->verbose) {
		tprintf("PES Extractor callback %d:%s pid 0x%04x 0x%08" PRIx64 " pes's\n",
			stream->nr, stream->iname, pid->pid, pid->peslistcount);
	}
#endif
	return NULL;
}

int input_stream_pid_write(struct pid_s *pid, const uint8_t *pkts, int packetCount)
{
	return ltntstools_pes_extractor_write(pid->pe, pkts, packetCount);
}

struct pid_s *input_stream_pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_e type)
{
	struct pid_s *pid = calloc(1, sizeof(*pid));
	if (!pid) {
		return NULL;
	}

	pid->pid = pidnr;
	pid->outputPidNr = outputPidNr;
	pid->streamId = streamId;
	pid->type = type;
	pthread_mutex_init(&pid->peslistlock, NULL);
	xorg_list_init(&pid->peslist);
	pthread_mutex_init(&pid->tilistlock, NULL);
	xorg_list_init(&pid->tilist);

	input_stream_pid_set_state(pid, PS_SCHEDULE_NEXT_PACKET);

	clock_gettime(CLOCK_MONOTONIC, &pid->last_pcr_output);

	if (ltntstools_vbv_profile_defaults(&pid->dp, VBV_CODEC_H264, 32, 59.94) < 0) {
		fprintf(stderr, "Unable to allocate VBV size for profile, aborting.\n");
		exit(0);
	}
	if (ltntstools_vbv_profile_validate(&pid->dp) == 0) {
		fprintf(stderr, "invalid decoder profile, aborting.\n");
		exit(0);
	}

	if (ltntstools_pes_extractor_alloc(&pid->pe, pid->pid, pid->streamId, (pes_extractor_callback)input_stream_pid_pe_callback,
		pid, (1024 * 1024), (2 * 1024 * 1024)) < 0)
	{
		fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
		exit(1);
	}

	uint16_t pcrPid = 0;
	switch(pidnr) {
	case 0x31:
	case 0x32:
		pcrPid = 0x31; /* TODO: hardcoded */
		break;
	}
	ltntstools_pes_extractor_set_pcr_pid(pid->pe, pcrPid);

	if (pid->type == PID_VIDEO) {
		if (ltntstools_vbv_alloc(&pid->vbv, pid->outputPidNr, (vbv_callback)input_stream_pid_vbv_callback, pid, &pid->dp) < 0) {
			fprintf(stderr, "invalid vbv context, aborting.\n");
			exit(0);
		}
	}

	return pid;
}

void input_stream_pid_free(struct pid_s *pid)
{
	/* Free any pes item obejcts */
	pthread_mutex_lock(&pid->peslistlock);
	while (!xorg_list_is_empty(&pid->peslist)) {

		struct pes_item_s *item = xorg_list_first_entry(&pid->peslist, struct pes_item_s, list);
		pid->peslistcount--;
		xorg_list_del(&item->list);

		pes_item_free(item);
	}
	pthread_mutex_unlock(&pid->peslistlock);

	/* Free any timing item contexts */
	pthread_mutex_lock(&pid->tilistlock);
	while (!xorg_list_is_empty(&pid->tilist)) {
		struct timing_item_s *ti = xorg_list_first_entry(&pid->tilist, struct timing_item_s, list);
		xorg_list_del(&ti->list);
		timing_item_free(ti);
	}
	pthread_mutex_unlock(&pid->tilistlock);

	if (pid->vbv) {
		ltntstools_vbv_free(pid->vbv);
		pid->vbv = NULL;
	}

	if (pid->pe) {
		ltntstools_pes_extractor_free(pid->pe);
		pid->pe = NULL;
	}

	if (pid->pkts) {
		free(pid->pkts);
		pid->pkts = NULL;
	}

	if (pid->pkts_outputSTC) {
		free(pid->pkts_outputSTC);
		pid->pkts_outputSTC = NULL;
	}

	free(pid);
}

void input_stream_pid_set_state(struct pid_s *pid, enum pid_state_e state)
{
	pid->state = state;
}

enum pid_state_e input_stream_pid_get_state(struct pid_s *pid)
{
	return pid->state;
}

struct pid_s *input_stream_pid_lookup(struct pid_s *pid, struct input_stream_s *is)
{
	for (int i = 0; i < is->pidCount; i++) {
		/* Find a matching pid, for now we'll match exclusively on transport pid number */
		if (pid->pid == is->pids[i]->pid) {
			return is->pids[i]; /* Success */
		}
	}

	return NULL; /* Failed */
}