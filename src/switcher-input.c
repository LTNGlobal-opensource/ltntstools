/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"

static void *vbv_notifications(void *userContext, enum ltntstools_vbv_event_e event)
{
	struct pid_s *pid = (struct pid_s *)userContext;

	struct timeval now;
	gettimeofday(&now, NULL);

	tprintf("pid 0x%04x (%04d) %s\n",
		pid->outputPidNr, pid->outputPidNr,
		ltntstools_vbv_event_name(event));

	return NULL;
}

static void *pe_callback(struct pid_s *pid, struct ltn_pes_packet_s *pes)
{
	struct input_stream_s *stream = pid->stream;
	struct output_stream_s *os = stream->ctx->outputStream;

	if (stream->ctx->verbose) {
		tprintf("pes->pid 0x%02x pts %14" PRIi64 " dts %14" PRIi64 " pcr %14" PRIi64 ", length %d\n", pid->outputPidNr, pes->PTS, pes->DTS, pes->pcr, pes->dataLengthBytes);
	}
#if 0
	if (pid->vbv && pid->type == PID_VIDEO && ltntstools_vbv_write(pid->vbv, (const struct ltn_pes_packet_s *)pes) < 0) {
		fprintf(stderr, "Error writing PES to VBV\n");
	}
#endif
	struct pes_item_s *item = pes_item_alloc(pid, pes, os);
	if (item) {
		pthread_mutex_lock(&pid->peslistlock);
		xorg_list_append(&item->list, &pid->peslist);
		pid->peslistcount++;
		pthread_mutex_unlock(&pid->peslistlock);

		// pes_item_dump(item, 1);

	} else {
		//ltn_pes_packet_dump(pes, "");
		ltn_pes_packet_free(pes);
	}

	if (stream->ctx->verbose) {
		tprintf("PES Extractor callback %d:%s pid 0x%04x 0x%08" PRIx64 " pes's\n",
			stream->nr, stream->iname, pid->pid, pid->peslistcount);
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

	if (stream->sm && stream->smcomplete == 0) {
		struct timeval nowtv;
		gettimeofday(&nowtv, NULL);
		ltntstools_streammodel_write(stream->sm, pkts, packetCount, &stream->smcomplete, &nowtv);

		if (stream->smcomplete) {
			if (ltntstools_streammodel_query_model(stream->sm, &stream->smpat) == 0) {
				tprintf("stream[%d]: PSIP model arrived\n", stream->nr);

				if (stream->ctx->verbose) {
					ltntstools_pat_dprintf(stream->smpat, STDOUT_FILENO);
				}

				if (input_stream_model_supported(stream) == 0) {
					tprintf("stream[%d]: PSIP model is not supported\n", stream->nr);
				} else {
					tprintf("stream[%d]: PSIP model is fully supported\n", stream->nr);
				}

				/* Don't free the pat, we'll don't on to it
				* ltntstools_pat_free(stream->smpat);
				*/
			}
		}
	}

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
		input_stream_write(stream, stream->pids[i], pkts, packetCount);
	}

	ltntstools_pid_stats_update(stream->libstats, pkts, packetCount);

	return NULL;
}

static void *_avio_raw_callback_status(struct input_stream_s *stream, enum source_avio_status_e status)
{
	switch (status) {
	case AVIO_STATUS_MEDIA_START:
		tprintf("AVIO media starts: %s\n", stream->iname);
		break;
	case AVIO_STATUS_MEDIA_END:
		tprintf("AVIO media ends: %s\n", stream->iname);
		//g_running = 0;
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}

void input_stream_show_codec_stats(struct input_stream_s *is)
{
	for (int i = 0; i < is->pidCount; i++) {
		struct pid_s *pid = is->pids[i];

		if (pid->type == PID_VIDEO) {
			tprintf("stream[%d].pid 0x%04x AVC: I/B/P = %" PRIu64 "/%" PRIu64 "/%" PRIu64 ", %" PRIu64 " slices.\n",
				is->nr, pid->pid,
				pid->count_frames_i, pid->count_frames_b, pid->count_frames_p,
				pid->count_frames_i + pid->count_frames_b + pid->count_frames_p);
		}

	}
	// printf("Pruned[%d] %d\n", is->nr, pruned);
}

void input_stream_prune_history(struct input_stream_s *is)
{
	/* Lock the pes list
	 * remove anything older than 10 seconds.
	 */
	time_t expire = time(NULL) - 10;

	int pruned = 0;

	for (int i = 0; i < is->pidCount; i++) {
		struct pid_s *pid = is->pids[i];

		pthread_mutex_lock(&pid->peslistlock);
		struct pes_item_s *item = NULL, *next = NULL;
		xorg_list_for_each_entry_safe(item, next, &pid->peslist, list) {
			if (item->created < expire) {
				xorg_list_del(&item->list);
				pes_item_free(item);
				pid->peslistcount--;
				pruned++;
			}
		}
		pthread_mutex_unlock(&pid->peslistlock);
	}
	// printf("Pruned[%d] %d\n", is->nr, pruned);
}

struct input_stream_s *input_stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr)
{
	struct input_stream_s *stream = calloc(1, sizeof(*stream));
	if (!stream) {
		return NULL;
	}

	stream->nr = nr;
	stream->ctx = ctx;
	stream->pidCount = 0;
	stream->iname = strdup(iname);

	if (ltntstools_streammodel_alloc(&stream->sm, stream) < 0) {
		fprintf(stderr, "Unable to allocate streammodel object.\n");
		free(stream);
		return NULL;
	}

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

int input_stream_add_pid(struct input_stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId)
{
	struct pid_s *pid = input_pid_alloc(pidnr, streamId, outputPidNr, streamId == 0xe0 ? PID_VIDEO : PID_AUDIO);
	pid->stream = stream;
	stream->pids[ stream->pidCount++ ] = pid;
	return 0; /* Success */
}

int input_stream_write(struct input_stream_s *stream, struct pid_s *pid, const uint8_t *pkts, int packetCount)
{
	return ltntstools_pes_extractor_write(pid->pe, pkts, packetCount);
}

void input_stream_free(struct input_stream_s *stream)
{
	ltntstools_source_avio_free(stream->avio_ctx);
	for (int i = 0; i < stream->pidCount; i++) {
		input_pid_free(stream->pids[i]);
	}
	free(stream->iname);
	ltntstools_pid_stats_free(stream->libstats);

	if (stream->smpat) {
		stream->smcomplete = 0;
		ltntstools_pat_free(stream->smpat);
		stream->smpat = NULL;
	}

	if (stream->sm) {
		ltntstools_streammodel_free(stream->sm);
		stream->sm = NULL;
	}

	free(stream);
}

struct pid_s *input_pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_e type)
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

	input_pid_set_state(pid, PS_SCHEDULE_NEXT_PACKET);

	clock_gettime(CLOCK_MONOTONIC, &pid->last_pcr_output);

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
		pcrPid = 0x31; /* TODO: hardcoded */
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
	pthread_mutex_lock(&pid->peslistlock);
	while (!xorg_list_is_empty(&pid->peslist)) {

		struct pes_item_s *item = xorg_list_first_entry(&pid->peslist, struct pes_item_s, list);
		pid->peslistcount--;
		xorg_list_del(&item->list);

		pes_item_free(item);
	}
	pthread_mutex_unlock(&pid->peslistlock);

	ltntstools_vbv_free(pid->vbv);
	ltntstools_pes_extractor_free(pid->pe);

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

void input_pid_set_state(struct pid_s *pid, enum pid_state_e state)
{
	pid->state = state;
}

enum pid_state_e input_pid_get_state(struct pid_s *pid)
{
	return pid->state;
}

/* Determine if two different models are compatible and supported by this tool. */
int input_stream_models_compatible(struct input_stream_s *is1, struct input_stream_s *is2)
{
	if (!is1 || !is2) {
		tprintf("stream[?]: missing models, invalid arg\n");
		return -1; /* Missing models */
	}

	if (is1->smcomplete == 0 || is1->smpat == NULL) {
		tprintf("stream[?]: stream 1 or 2 is not yet complete\n");
		return -1; /* Incomplete model */
	}
	if (is2->smcomplete == 0 || is2->smpat == NULL) {
		tprintf("stream[?]: stream 1 or 2 is not yet complete (PAT)\n");
		return -1; /* Incomplete model */
	}

	if (input_stream_model_supported(is1) != 1) {
		tprintf("stream[%d]: model is not supported\n", is1->nr);
		return -1; /* Unsupported models */
	}
	if (input_stream_model_supported(is2) != 1) {
		tprintf("stream[%d]: model is not supported\n", is2->nr);
		return -1; /* Unsupported models */
	}

	if (is1->smpat->program_count != 1 || is2->smpat->program_count != 1) {
		tprintf("stream[%d]: program count (%d) is different to model 2 (%d), unsupported\n",
			is1->nr,
			is1->smpat->program_count,
			is2->smpat->program_count);
		return -1; /* Multiple programs, never sure what we're comparing. */
	}

	if (is1->smpat->programs[0].pmt.stream_count != is2->smpat->programs[0].pmt.stream_count) {
		tprintf("stream[%d]: program1 stream count (%d) is different to model2.program1 stream count (%d), unsupported\n",
			is1->nr,
			is1->smpat->programs[0].pmt.stream_count,
			is2->smpat->programs[0].pmt.stream_count);
		return -1; /* Multiple programs, never sure what we're comparing. */
	}

	if (ltntstools_pmt_compare(&is1->smpat->programs[0].pmt, &is2->smpat->programs[0].pmt) != 1) {
		/* Might be something as simple as the ltn encoder version from each stream is different */
		tprintf("stream[%d]: PMT of first entry doesn't match model 2. Continuing but that's a red flag.\n",
			is1->nr);
	}

	return 1; /* Success. Both models are compatible with each other */
}

/* Check the stream configuration, determine if this tools supports it. */
int input_stream_model_supported(struct input_stream_s *is)
{
	int e = 0;
	int foundAVC = 0;
	int foundAC3 = 0;
	int foundMP1L2 = 0;

	struct ltntstools_pmt_s *pmt = NULL;

	if (!is) {
		return -1; /* Failed */
	}

	if (!is->sm || !is->smpat || !is->smcomplete) {
		/* No model, or model not complete */
		return -1; /* Failed */
	}

	/* Rules
	 * SPTS only.
	 * AVC only.
	 * MP1L2 only
	 * Same format and framerate (we can't check that)
	*/

	e = 0;
	pmt = NULL;
	while (ltntstools_pat_enum_services_video(is->smpat, &e, &pmt) == 0) {
		for (unsigned int i = 0; i < pmt->stream_count; i++) {
			if (pmt->streams[i].stream_type == 0x1b /* AVC */) {
				foundAVC = 1;
			} else
			if (pmt->streams[i].stream_type == 0x81 /* AC3 */) {
				foundAC3 = 1;
			} else
			if (pmt->streams[i].stream_type == 0x04 /* MP1L2 */) {
				foundMP1L2 = 1;
			}
		}
		break; /* The first service with video is checked, SPTS */
	}

	if (!foundAVC || foundMP1L2 || !foundAC3) {
		return 0; /* Success, model is not supported */
	}

	return 1; /* Success, model is supported */
}

int input_stream_flush_to_frame(struct input_stream_s *is)
{
	tprintf("stream[%d] discarding everything to next iframe\n", is->nr);
	struct pes_item_s *itemVideo = NULL;

	/* For each input pid, find video FIRST */
	for (int p = 0; p < is->pidCount; p++) {
		struct pid_s *pid = is->pids[p];

		if (pid->type == PID_VIDEO) {

			int dropped = 0;

			/* Drop everything until the next iframe */
			pthread_mutex_lock(&pid->peslistlock);
			struct pes_item_s *item = NULL, *next = NULL;
			xorg_list_for_each_entry_safe(item, next, &pid->peslist, list) {

				if (item->video.sliceType == SLICE_I) {
					itemVideo = item; /* We want the item for later */

					/* Validate assumptions. We're assuming we'll have these along with the iframe. */

					if (!ltn_pes_packet_has_PTS(item->pes)) {
						tprintf("stream[%d] trimming to iframe, but iframe doesn't have a PTS. Warning.\n");
					} else {
						if (item->pes->PTS <= 0) {
							tprintf("stream[%d] trimming to iframe, but iframe PTS is 0 or < 0. Warning.\n");
						}
					}
					if (!item->video.has_avc_aud) {
						tprintf("stream[%d] trimming to iframe, but iframe doesn't have an attached AUD. Warning.\n");
					}
					if (!item->video.has_avc_sps) {
						tprintf("stream[%d] trimming to iframe, but iframe doesn't have an attached SPS. Warning.\n");
					}
					if (!item->video.has_avc_pps) {
						tprintf("stream[%d] trimming to iframe, but iframe doesn't have an attached PPS. Warning.\n");
					}

					break;
				}

				xorg_list_del(&item->list);
				pid->peslistcount--;

				pes_item_free(item);

				dropped++;
			}
			pthread_mutex_unlock(&pid->peslistlock);
			tprintf("stream[%d].pid 0x%04x dropped %d VideoPES items, found iframe\n", is->nr, pid->pid, dropped);

		}
	}

	/* For each input pid, other than video */
	for (int p = 0; p < is->pidCount; p++) {
		struct pid_s *pid = is->pids[p];

		if (pid->type == PID_AUDIO) {

			int dropped = 0;

			/* Drop everything until the next PTS >= video.pts */
			pthread_mutex_lock(&pid->peslistlock);
			struct pes_item_s *item = NULL, *next = NULL;
			xorg_list_for_each_entry_safe(item, next, &pid->peslist, list) {

/* TODO: Assuming we have a pts */
				if (item->pes->PTS < itemVideo->pes->PTS) {
					xorg_list_del(&item->list);
					pid->peslistcount--;
					pes_item_free(item);

					dropped++;
				} else {
					break;
				}

			}
			pthread_mutex_unlock(&pid->peslistlock);
			tprintf("stream[%d].pid 0x%04x dropped %d AudioPES items, until PTS %" PRIi64 "\n",
				is->nr, pid->pid, dropped, itemVideo->pes->PTS);
		}

	}

	/* For each input pid, everything else */
	for (int p = 0; p < is->pidCount; p++) {
		struct pid_s *pid = is->pids[p];
		if (pid->type == PID_OTHER) {
			tprintf("stream[%d].pid 0x%04x IMPLEMENT ME\n", is->nr, pid->pid);
		}
	}

	return 0; /* Success */
}
