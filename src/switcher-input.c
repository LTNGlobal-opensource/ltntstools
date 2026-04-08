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

static void *pe_callback(struct pid_s *pid, struct ltn_pes_packet_s *pes)
{
	struct input_stream_s *stream = pid->stream;
	if (stream->ctx->verbose) {
		printf("pes->pid 0x%02x pts %14" PRIi64 " dts %14" PRIi64 " pcr %14" PRIi64 "\n", pid->outputPidNr, pes->PTS, pes->DTS, pes->pcr);
	}
	if (pid->pid == 0x32) {
		//ltntstools_hexdump(pes->rawBuffer, 188, 32);
	}
#if 0
	if (pid->vbv && pid->type == PID_VIDEO && ltntstools_vbv_write(pid->vbv, (const struct ltn_pes_packet_s *)pes) < 0) {
		fprintf(stderr, "Error writing PES to VBV\n");
	}
#endif
	struct pes_item_s *e = malloc(sizeof(*e));
	if (e) {
		e->pes = pes;
		e->arrivalSTC = output_get_computed_stc(stream->ctx); /* We got the pes at the current STC */

		if (pid->type == PID_VIDEO) {
			e->outputSTC = output_get_computed_stc(stream->ctx) + (27000 * 200); /* We'll schedule for output in 200ms */
		} else 
		if (pid->type == PID_AUDIO) {
			e->outputSTC = 0; // get_computed_stc(stream->ctx);
		}

		pthread_mutex_lock(&pid->peslistlock);
		xorg_list_append(&e->list, &pid->peslist);
		pid->peslistcount++;
		pthread_mutex_unlock(&pid->peslistlock);
	} else {
		//ltn_pes_packet_dump(pes, "");
		ltn_pes_packet_free(pes);
	}

	if (stream->ctx->verbose) {
		printf("PES Extractor callback %d:%s pid 0x%04x 0x%08" PRIx64 " pes's\n", stream->nr, stream->iname, pid->pid, pid->peslistcount);
	}

	return NULL;
}


static void *notification_callback(struct input_stream_s *stream, enum ltntstools_notification_event_e event,
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
			stream->nr,
			ltntstools_pid_stats_stream_get_cc_errors((struct ltntstools_stream_statistics_s *)stats));
	} else
	if (0 && event == EVENT_UPDATE_STREAM_MBPS) {
		printf("%d.%06d: %-40s stream %p nr %d %5.2f mbps\n", (int)ts.tv_sec, (int)ts.tv_usec,
			ltntstools_notification_event_name(event),
			stats,
			stream->nr,
			ltntstools_pid_stats_stream_get_mbps((struct ltntstools_stream_statistics_s *)stats));
	} else
	if (event == EVENT_UPDATE_STREAM_IAT_HWM) {
		printf("%d.%06d: %-40s stream %p nr %d %" PRIi64 " ms\n", (int)ts.tv_sec, (int)ts.tv_usec,
			ltntstools_notification_event_name(event),
			stats,
			stream->nr,
			ltntstools_pid_stats_stream_get_iat_hwm_us((struct ltntstools_stream_statistics_s *)stats) / 1000);
	} else
	if (0 && event == EVENT_UPDATE_PID_PUSI_DELIVERY_TIME) {

		/* Find the pid from the stats in our stream struct */
		int64_t ms = pid->pusi_time_ms;
		struct pid_s *opid = NULL;
		for (int i = 0; i < stream->pidCount; i++) {
			//printf("pid->pidNr 0x%04x finding.... %04x\n", pid->pidNr, stream->pids[i]->pid);
			if (stream->pids[i]->pid == pid->pidNr) {
				opid = stream->pids[i];
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


static void *_avio_raw_callback(struct input_stream_s *stream, const uint8_t *pkts, int packetCount)
{
	//printf("AVIO data: %s nr %d %d packets\n", stream->iname, stream->nr, packetCount);

	for (int i = 0; i < stream->pidCount; i++) {
		if (i == 0) {
			struct stat s;
			char fn[64];
			sprintf(fn, "/tmp/stream%d.drop", stream->nr);
			if (stat(fn, &s) == 0) {
				/* Trash the cc in the first packet */
				unsigned char *p =(unsigned char *)pkts;
				*(p + 3) = 0x30;
				remove(fn);
			}
		}
		stream_write(stream, stream->pids[i], pkts, packetCount);
	}

	ltntstools_pid_stats_update(stream->libstats, pkts, packetCount);

	return NULL;
}

static void *_avio_raw_callback_status(struct input_stream_s *stream, enum source_avio_status_e status)
{
	switch (status) {
	case AVIO_STATUS_MEDIA_START:
		printf("AVIO media starts: %s\n", stream->iname);
		break;
	case AVIO_STATUS_MEDIA_END:
		printf("AVIO media ends: %s\n", stream->iname);
		g_running = 0;
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}

struct input_stream_s *stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr)
{
	struct input_stream_s *stream = calloc(1, sizeof(*stream));
	if (!stream) {
		return NULL;
	}

	stream->nr = nr;
	stream->ctx = ctx;
	stream->pidCount = 0;
	stream->iname = strdup(iname);

	/* We use this specifically for tracking PCR walltime drift */
	ltntstools_pid_stats_alloc(&stream->libstats);
	ltntstools_notification_register_callback(stream->libstats, EVENT_UPDATE_STREAM_MBPS, stream, (ltntstools_notification_callback)notification_callback);
	ltntstools_notification_register_callback(stream->libstats, EVENT_UPDATE_STREAM_IAT_HWM, stream, (ltntstools_notification_callback)notification_callback);
	ltntstools_pid_stats_pid_set_contains_pcr(stream->libstats, 0x31); /* TODO: Fixed */
	
	stream->cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	stream->cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;

	int ret = ltntstools_source_avio_alloc(&stream->avio_ctx, stream, &stream->cbs, stream->iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		free(stream);
		return NULL;
	}

	return stream;
}

int stream_add_pid(struct input_stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId)
{
	struct pid_s *pid = pid_alloc(pidnr, streamId, outputPidNr, streamId == 0xe0 ? PID_VIDEO : PID_AUDIO);
	pid->stream = stream;
	stream->pids[ stream->pidCount++ ] = pid;
	return 0; /* Success */
}

int stream_write(struct input_stream_s *stream, struct pid_s *pid, const uint8_t *pkts, int packetCount)
{
	return ltntstools_pes_extractor_write(pid->pe, pkts, packetCount);
}

void stream_free(struct input_stream_s *stream)
{
	ltntstools_source_avio_free(stream->avio_ctx);
	for (int i = 0; i < stream->pidCount; i++) {
		pid_free(stream->pids[i]);
	}
	free(stream->iname);
	free(stream);
}

struct pid_s *pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_t type)
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

	if (ltntstools_pes_extractor_alloc(&pid->pe, pid->pid, pid->streamId, (pes_extractor_callback)pe_callback,
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

void pid_free(struct pid_s *pid)
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
