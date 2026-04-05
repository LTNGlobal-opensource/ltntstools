/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"


static void *vbv_notifications(void *userContext, enum ltntstools_vbv_event_e event)
{
	struct pid_s *pid = (struct pid_s *)userContext;
	//struct stream_s *stream = pid->stream;
	//struct tool_ctx_s *ctx = stream->ctx;

	struct timeval now;
	gettimeofday(&now, NULL);

	printf("%d.%06d: pid 0x%04x (%04d) %s\n",
		(int)now.tv_sec, (int)now.tv_usec,
		pid->outputPidNr, pid->outputPidNr,
		ltntstools_vbv_event_name(event));

	return NULL;
}

static void *input_pe_callback(struct pid_s *pid, struct ltn_pes_packet_s *pes)
{
	struct input_stream_s *is = pid->stream;
	struct output_stream_s *os = pid->stream->ctx->outputStream;

	if (is->ctx->verbose) {
		printf("pes->pid 0x%02x pts %14" PRIi64 " dts %14" PRIi64 " pcr %14" PRIi64 "\n", pid->outputPidNr, pes->PTS, pes->DTS, pes->pcr);
	}
	if (pid->pid == 0x32) {
		//ltntstools_hexdump(pes->rawBuffer, 188, 32);
	}

	if (pid->vbv && pid->type == PID_VIDEO && ltntstools_vbv_write(pid->vbv, (const struct ltn_pes_packet_s *)pes) < 0) {
		fprintf(stderr, "Error writing PES to VBV\n");
	}

	struct pes_item_s *e = malloc(sizeof(*e));
	if (e) {
		e->pes = pes;
		e->arrivalSTC = output_get_computed_stc(os); /* We got the pes at the current STC */

		if (pid->type == PID_VIDEO) {
			e->outputSTC = output_get_computed_stc(os) + (27000 * 200); /* We'll schedule for output in 200ms */
		} else 
		if (pid->type == PID_AUDIO) {
			e->outputSTC = 0; // get_computed_stc(os);
		}

		pthread_mutex_lock(&pid->peslistlock);
		xorg_list_append(&e->list, &pid->peslist);
		pid->peslistcount++;
		pthread_mutex_unlock(&pid->peslistlock);
	} else {
		//ltn_pes_packet_dump(pes, "");
		ltn_pes_packet_free(pes);
	}

	if (is->ctx->verbose) {
		printf("PES Extractor callback %d:%s pid 0x%04x 0x%08" PRIx64 " pes's\n", is->nr, is->iname, pid->pid, pid->peslistcount);
	}

	return NULL;
}

struct pid_s *input_pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_t type)
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

	if (ltntstools_vbv_profile_defaults(&pid->dp, VBV_CODEC_H264, 32, 59.94) < 0) {
		fprintf(stderr, "Unable to allocate VBV size for profile, aborting.\n");
		exit(0);
	}
	if (ltntstools_vbv_profile_validate(&pid->dp) == 0) {
		fprintf(stderr, "invalid decoder profile, aborting.\n");
		exit(0);
	}
	if (ltntstools_vbv_alloc(&pid->vbv, pid->outputPidNr, (vbv_callback)vbv_notifications, pid, &pid->dp) < 0) {
		fprintf(stderr, "invalid vbv context, aborting.\n");
		exit(0);
	}

	if (ltntstools_pes_extractor_alloc(&pid->pe, pid->pid, pid->streamId, (pes_extractor_callback)input_pe_callback,
		pid, (1024 * 1024), (2 * 1024 * 1024)) < 0)
	{
		fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
		exit(1);
	}
	uint16_t pcrPid = 0;
	switch(pidnr) {
	case 0x31:
	case 0x32:
		pcrPid = 0x31;
		break;
	}
	ltntstools_pes_extractor_set_pcr_pid(pid->pe, pcrPid);

	if (pid->type == PID_VIDEO) {
		if (ltntstools_vbv_alloc(&pid->vbv, pid->outputPidNr, (vbv_callback)vbv_notifications, pid, &pid->dp) < 0) {
			fprintf(stderr, "invalid vbv context, aborting.\n");
			exit(0);
		}
	}

	return pid;
}

void input_pid_free(struct pid_s *pid)
{
	ltntstools_vbv_free(pid->vbv);
	ltntstools_pes_extractor_free(pid->pe);
	free(pid->pkts);

	pthread_mutex_lock(&pid->peslistlock);
	while (!xorg_list_is_empty(&pid->peslist)) {

		struct pes_item_s *e = xorg_list_first_entry(&pid->peslist, struct pes_item_s, list);
		pid->peslistcount--;
		xorg_list_del(&e->list);
		ltn_pes_packet_free(e->pes);
		free(e);

	}
	pthread_mutex_unlock(&pid->peslistlock);

	free(pid);
}


static void *_avio_raw_callback(struct input_stream_s *is, const uint8_t *pkts, int packetCount)
{
	//printf("AVIO data: %s nr %d %d packets\n", is->iname, is->nr, packetCount);

	for (int i = 0; i < is->pidCount; i++) {
		if (i == 0) {
			struct stat s;
			char fn[64];
			sprintf(fn, "/tmp/stream%d.drop", is->nr);
			if (stat(fn, &s) == 0) {
				/* Trash the cc in the first packet */
				unsigned char *p =(unsigned char *)pkts;
				*(p + 3) = 0x30;
				remove(fn);
			}
		}
		input_stream_write(is, is->pids[i], pkts, packetCount);
	}

	ltntstools_pid_stats_update(is->libstats, pkts, packetCount);

	return NULL;
}

static void *_avio_raw_callback_status(struct input_stream_s *is, enum source_avio_status_e status)
{
	switch (status) {
	case AVIO_STATUS_MEDIA_START:
		printf("AVIO media starts: %s\n", is->iname);
		break;
	case AVIO_STATUS_MEDIA_END:
		printf("AVIO media ends: %s\n", is->iname);
		g_running = 0;
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}

static void *input_notification_callback(struct input_stream_s *is, enum ltntstools_notification_event_e event,
	const struct ltntstools_stream_statistics_s *stats,
	const struct ltntstools_pid_statistics_s *pid)
{
	struct timeval ts;
	gettimeofday(&ts, NULL);

#if 0
	printf("%d.%06d: %s stream %p pid %p\n", (int)ts.tv_sec, (int)ts.tv_usec,
		ltntstools_notification_event_name(event),
		stats, pid);
#endif

	if (event == EVENT_UPDATE_STREAM_CC_COUNT) {
		printf("%d.%06d: %-40s stream %p nr %d %" PRIu64 " cc errors\n",
			(int)ts.tv_sec,
			(int)ts.tv_usec,
			ltntstools_notification_event_name(event),
			stats,
			is->nr,
			ltntstools_pid_stats_stream_get_cc_errors((struct ltntstools_stream_statistics_s *)stats));
	} else
	if (0 && event == EVENT_UPDATE_STREAM_MBPS) {
		printf("%d.%06d: %-40s stream %p nr %d %5.2f mbps\n", (int)ts.tv_sec, (int)ts.tv_usec,
			ltntstools_notification_event_name(event),
			stats,
			is->nr,
			ltntstools_pid_stats_stream_get_mbps((struct ltntstools_stream_statistics_s *)stats));
	} else
	if (event == EVENT_UPDATE_STREAM_IAT_HWM) {
		printf("%d.%06d: %-40s stream %p nr %d %" PRIi64 " ms\n", (int)ts.tv_sec, (int)ts.tv_usec,
			ltntstools_notification_event_name(event),
			stats,
			is->nr,
			ltntstools_pid_stats_stream_get_iat_hwm_us((struct ltntstools_stream_statistics_s *)stats) / 1000);
	} else
	if (0 && event == EVENT_UPDATE_PID_PUSI_DELIVERY_TIME) {

		/* Find the pid from the stats in our stream struct */
		int64_t ms = pid->pusi_time_ms;
		struct pid_s *opid = NULL;
		for (int i = 0; i < is->pidCount; i++) {
			//printf("pid->pidNr 0x%04x finding.... %04x\n", pid->pidNr, stream->pids[i]->pid);
			if (is->pids[i]->pid == pid->pidNr) {
				opid = is->pids[i];
				break;
			}
		}

		/* opid can be null if this app is given a pid for which we're not tracking (such as a second audio channel. */
		if (opid && opid->type == PID_VIDEO) {
			printf("%d.%06d: %-40s stream %p ipid %p/0x%04x opid %p/0x%04x/0x%04x % 6" PRIi64 " ms\n", (int)ts.tv_sec, (int)ts.tv_usec,
				ltntstools_notification_event_name(event),
				stats,
				pid, pid->pidNr,
				opid, opid->pid, opid->outputPidNr,
				ms);
		} else {
#if 0
			printf("%d.%06d: %s stream %p ipid %p/0x%04x: opid %p %+6" PRIi64 " ms\n", (int)ts.tv_sec, (int)ts.tv_usec,
				ltntstools_notification_event_name(event),
				stats,
				pid, pid->pidNr,
				opid,
				ms);
#endif
		}
	}
	return NULL;	
}

struct input_stream_s *input_stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr)
{
	struct input_stream_s *is = calloc(1, sizeof(*is));
	if (!is) {
		return NULL;
	}

	is->nr = nr;
	is->ctx = ctx;
	is->pidCount = 0;
	is->iname = strdup(iname);

	/* We use this specifically for tracking PCR walltime drift */
	ltntstools_pid_stats_alloc(&is->libstats);
	ltntstools_notification_register_callback(is->libstats, EVENT_UPDATE_STREAM_MBPS, is, (ltntstools_notification_callback)input_notification_callback);
	ltntstools_notification_register_callback(is->libstats, EVENT_UPDATE_STREAM_IAT_HWM, is, (ltntstools_notification_callback)input_notification_callback);
	ltntstools_pid_stats_pid_set_contains_pcr(is->libstats, 0x31); /* TODO: Fixed */
	
	is->cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	is->cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;

	int ret = ltntstools_source_avio_alloc(&is->avio_ctx, is, &is->cbs, is->iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		free(is);
		return NULL;
	}

	return is;
}

int input_stream_add_pid(struct input_stream_s *is, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId)
{
	struct pid_s *pid = input_pid_alloc(pidnr, streamId, outputPidNr, streamId == 0xe0 ? PID_VIDEO : PID_AUDIO);
	pid->stream = is;
	is->pids[ is->pidCount++ ] = pid;

	return 0; /* Success */
}

int input_stream_write(struct input_stream_s *is, struct pid_s *pid, const uint8_t *pkts, int packetCount)
{
	return ltntstools_pes_extractor_write(pid->pe, pkts, packetCount);
}

void input_stream_free(struct input_stream_s *is)
{
	ltntstools_source_avio_free(is->avio_ctx);
	for (int i = 0; i < is->pidCount; i++) {
		input_pid_free(is->pids[i]);
	}
	free(is->iname);
	free(is);
}
