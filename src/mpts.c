/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"
#include "xorg-list.h"

#define MAX_INPUT_STREAMS        16
#define MAX_STREAM_PIDS           2
#define TARGET_BITRATE     40000000 // bps
#define TS_PACKET_SIZE          188
#define TS_PACKETS_PER_SEC (TARGET_BITRATE / (TS_PACKET_SIZE * 8))
#define PACKET_INTERVAL_NS (1000000000 / TS_PACKETS_PER_SEC)
#define MAX_EBN_SIZE 834 * 1000

struct pid_s;
struct stream_s;
struct tool_ctx_s;

enum pid_type_t {
	PID_UNDEFINED,
	PID_VIDEO,
	PID_AUDIO
};

struct stream_s *stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr);
int stream_add_pid(struct stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId);
int stream_write(struct stream_s *stream, struct pid_s *pid, const uint8_t *pkts, int packetCount);
void stream_free(struct stream_s *stream);

struct pid_s *pid_alloc(uint16_t pidnr, uint8_t streamId, uint16_t outputPidNr, enum pid_type_t type);
void pid_free(struct pid_s *pid);

struct pes_item_s
{
	struct xorg_list list;
	struct ltn_pes_packet_s *pes;
	int64_t arrivalSTC; /* local STC clock value when we first got the pes */
	int64_t outputSTC;  /* the local STC clock value when the pes is scheduled for output */
};

struct pid_s
{
	struct stream_s *stream;
	enum pid_type_t type;

	uint16_t pid;
	uint16_t outputPidNr;
	uint8_t streamId;
	void *pe;

	pthread_mutex_t peslistlock;
	uint64_t peslistcount;
	struct xorg_list peslist;

	/* Transport packets to be egressed */
	uint8_t  *pkts;
	uint32_t  pkts_count;
	uint32_t  pkts_idx;
	int64_t  *pkts_outputSTC;
	uint8_t cc;
	uint8_t ccRoller;

	struct timespec lastOutputPCR; /* STC ticks */
	uint8_t pkt_scr[188];

	/* Video Buffer Verifier (VBV) */
	void *vbv;
	struct vbv_decoder_profile_s dp;
};

struct stream_s
{
	struct tool_ctx_s *ctx;
	int nr;
	char *iname;

	void *avio_ctx;
	struct ltntstools_source_avio_callbacks_s cbs;

	struct ltntstools_stream_statistics_s *libstats;

	int pidCount;
	struct pid_s *pids[MAX_STREAM_PIDS];
};

struct tool_ctx_s
{
	int verbose;
	int inputNr;

	int64_t ticks_per_outputts27MHz;
	
	uint8_t null_pkt[188];
	int64_t null_pkt_outputSTC;

	uint8_t psip_cc[3];
	uint8_t psip_pkt[3][188];

	struct ltntstools_reframer_ctx_s *reframer;
	struct sockaddr_in addr;
	int sockfd;
	int64_t ts_packets_sent;

	struct timespec next_time;
	struct timespec last_psip;
	struct timespec last_q_report;
	int output_psip_idx;

	/* Streams */
	struct stream_s *streams[MAX_INPUT_STREAMS];
	struct ltntstools_pat_s *pat;

	/* Stream scheduling */
	uint32_t schedule_idx;
	int schedule_entries;
	struct pid_s *schedule[4];

};

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

int64_t get_computed_stc(struct tool_ctx_s *ctx)
{
	double startupPacketsSent = 10000;
	double bitsTransmitted = (startupPacketsSent + ctx->ts_packets_sent) * TS_PACKET_SIZE * 8.0;
	double additionalBits = 0.0;
	double bps = TARGET_BITRATE;

	return (((bitsTransmitted + additionalBits) / bps) * (double)27000000);
}

static int g_running = 1;
static void signal_handler(int signum)
{
	g_running = 0;
}

static void *pe_callback(struct pid_s *pid, struct ltn_pes_packet_s *pes)
{
	struct stream_s *stream = pid->stream;
	if (stream->ctx->verbose) {
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
		e->arrivalSTC = get_computed_stc(stream->ctx); /* We got the pes at the current STC */

		if (pid->type == PID_VIDEO) {
			e->outputSTC = get_computed_stc(stream->ctx) + (27000 * 200); /* We'll schedule for output in 200ms */
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

static void *_avio_raw_callback(struct stream_s *stream, const uint8_t *pkts, int packetCount)
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

static void *_avio_raw_callback_status(struct stream_s *stream, enum source_avio_status_e status)
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

static void *notification_callback(struct stream_s *stream, enum ltntstools_notification_event_e event,
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

struct stream_s *stream_alloc(struct tool_ctx_s *ctx, char *iname, int nr)
{
	struct stream_s *stream = calloc(1, sizeof(*stream));
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

int stream_add_pid(struct stream_s *stream, uint16_t pidnr, uint16_t outputPidNr, uint8_t streamId)
{
	struct pid_s *pid = pid_alloc(pidnr, streamId, outputPidNr, streamId == 0xe0 ? PID_VIDEO : PID_AUDIO);
	pid->stream = stream;
	stream->pids[ stream->pidCount++ ] = pid;
	return 0; /* Success */
}

int stream_write(struct stream_s *stream, struct pid_s *pid, const uint8_t *pkts, int packetCount)
{
	return ltntstools_pes_extractor_write(pid->pe, pkts, packetCount);
}

void stream_free(struct stream_s *stream)
{
	ltntstools_source_avio_free(stream->avio_ctx);
	for (int i = 0; i < stream->pidCount; i++) {
		pid_free(stream->pids[i]);
	}
	free(stream->iname);
	free(stream);
}

void *reframer_callback(struct tool_ctx_s *ctx, const uint8_t *buf, int lengthBytes)
{
	sendto(ctx->sockfd, buf, lengthBytes, 0, (struct sockaddr *)&ctx->addr, sizeof(ctx->addr));
	return NULL;
}

int timesec_diff(struct timespec next_time, struct timespec last_time)
{
	struct timespec diff;
	diff.tv_sec = next_time.tv_sec - last_time.tv_sec;
	diff.tv_nsec = next_time.tv_nsec - last_time.tv_nsec;
	if (diff.tv_nsec < 0) {
		diff.tv_sec -= 1;
		diff.tv_nsec += 1000000000L;
	}

	int ms = diff.tv_sec + diff.tv_nsec / 1e6;
	return ms;
}

void service(struct tool_ctx_s *ctx)
{
	struct pid_s *outputPid = NULL;

	if (timesec_diff(ctx->next_time, ctx->last_q_report) >= 950) {
		ctx->last_q_report = ctx->next_time;

		struct timeval ts;
		gettimeofday(&ts, NULL);

		printf("%d.%06d: PES Queues/Size: ", (int)ts.tv_sec, (int)ts.tv_usec);
		for (int i = 0; i <= ctx->inputNr; i++) {
			struct stream_s *stream = ctx->streams[i];
			for (int j = 0; j < stream->pidCount; j++) {
				struct pid_s *pid = stream->pids[j];

				pthread_mutex_lock(&pid->peslistlock);
				printf("s%d.%04x %05" PRIu64 " ",
					stream->nr, pid->outputPidNr,
					pid->peslistcount);
				pthread_mutex_unlock(&pid->peslistlock);

			}
		}
		printf("\n");
	}

	if (timesec_diff(ctx->next_time, ctx->last_psip) > 50) {
		/* Generate the PSIP multiple times a second, and schedule them for output. */
		ctx->last_psip = ctx->next_time;
		ctx->output_psip_idx = 0; /* Throw a flag, start outputting the PSIO from packet 0 */
		ltntstools_pat_create_packet_ts(ctx->pat, ctx->psip_cc[0]++, &ctx->psip_pkt[0][0], 188);
		ltntstools_pmt_create_packet_ts(&ctx->pat->programs[0].pmt, ctx->pat->programs[0].program_map_PID, ctx->psip_cc[1]++, &ctx->psip_pkt[1][0], 188);
		ltntstools_pmt_create_packet_ts(&ctx->pat->programs[1].pmt, ctx->pat->programs[1].program_map_PID, ctx->psip_cc[2]++, &ctx->psip_pkt[2][0], 188);
	}

	/* Try to ensure we have TS packets available for all input streams, all pids.  */
	for (int s = 0; s <= ctx->inputNr; s++) {
		struct stream_s *stream = ctx->streams[s];
		for (int p = 0; p < stream->pidCount; p++) {
			struct pid_s *pid = stream->pids[p];

			struct pes_item_s *item = NULL;

			/* Cleanup previously used packet lists and related output clocks, free them. */
			if (pid->pkts && pid->pkts_count && pid->pkts_idx >= pid->pkts_count) {
				free(pid->pkts);
				pid->pkts = NULL;
				pid->pkts_count = 0;
				pid->pkts_idx = 0;
				free(pid->pkts_outputSTC);
				pid->pkts_outputSTC = NULL;
			}

			/* If this pid doesn't have any packets queued.... convert the next pes into TS */
			if (pid->pkts_count == 0) {
				/* Get more ts packets */

				pthread_mutex_lock(&pid->peslistlock);
				struct pes_item_s *e = NULL, *next = NULL;
				xorg_list_for_each_entry_safe(e, next, &pid->peslist, list) {
					if (e->outputSTC < get_computed_stc(ctx)) {
						item = e;
						xorg_list_del(&e->list);
						pid->peslistcount--;
						break;
					}
				}
				pthread_mutex_unlock(&pid->peslistlock);

				if (!item) {
					continue;
				}

				if (ltntstools_ts_packetizer_with_pcr(item->pes->rawBuffer,
					item->pes->rawBufferLengthBytes,
					&pid->pkts,
					&pid->pkts_count,
					188, &pid->cc, pid->outputPidNr,
					-1) < 0)
				{
					printf("Err\n");
				}

				if (ctx->verbose) {
					printf("Created %4d ts packets for pid 0x%04x\n", pid->pkts_count, pid->outputPidNr);
				}
				pid->pkts_idx = 0;

				/* Now compute the fine grain packet scheduling from the first, TS packet onwards */
				pid->pkts_outputSTC = calloc(sizeof(int64_t), pid->pkts_count);
				for (unsigned int i = 0; i < pid->pkts_count; i++) {

					int64_t ticks_per_ts = 0;

					if (pid->type == PID_VIDEO) {
						/* Determine for a given bitrate and packet size, how the output schedule should be timed. */
						double bitrate_mbps = 20.0 - 2; /* TODO: hardcoded 20mb mux, using 18mbps for video. */
						double bitrate_bps = bitrate_mbps * 1000000.0;
						double packet_duration_sec = (double)(188.0 * 8.0) / bitrate_bps;
						double ticks_per_packet = packet_duration_sec * 27000000.0;
						ticks_per_ts = ticks_per_packet;
					} else
					if (pid->type == PID_AUDIO) {
						/* Determine for a given bitrate and packet size, how the output schedule should be timed. */
						//double bitrate_mbps = 1.0; /* TODO: hardcoded 20mb mux, using 18mbps for video. */
						//double bitrate_bps = bitrate_mbps * 1000000.0;
						//double packet_duration_sec = (double)(188.0 * 8.0) / bitrate_bps;
						//double ticks_per_packet = packet_duration_sec * 27000000.0;
						//ticks_per_ts = ticks_per_packet;
					}

					pid->pkts_outputSTC[i] = item->outputSTC + (i * ticks_per_ts);
				}

				ltn_pes_packet_free(item->pes);
				free(item);
			}
		}
	} /* For all input stream, ensure we have TS packets available. */

	/* Each iteration through, we output a single packet. If we don't have a packet
		* in the schedule to send, then a NULL packet goes out.
		* "Only one ping Mr Borodin, one ping."
		*/

	uint8_t *pkt = NULL;

	if (ctx->output_psip_idx > -1) {
		/* Its time to output a PSIP packet, select one. */

		pkt = &ctx->psip_pkt[ ctx->output_psip_idx ][0];

		if (++ctx->output_psip_idx == 3) {
			ctx->output_psip_idx = -1;
		}

	}
	else {
		/* Its time to output a regular stream packet, select one.
		 * Using an input schedule forces pid interleaving.
		 */
		for (int i = 0; i < ctx->schedule_entries; i++) {
			ctx->schedule_idx = (ctx->schedule_idx + 1) % ctx->schedule_entries;
			struct pid_s *pid = ctx->schedule[ctx->schedule_idx];

			if (pid->type == PID_VIDEO && timesec_diff(ctx->next_time, pid->lastOutputPCR) > 30) {
				/* Generate the PSIP multiple times a second, and schedule them for output. */
				pid->lastOutputPCR = ctx->next_time;

				int64_t pcr;
				ltntstools_bitrate_calculator_query_stc(pid->stream->libstats, &pcr);
				ltntstools_generatePCROnlyPacket(&pid->pkt_scr[0], sizeof(pid->pkt_scr), pid->outputPidNr, &pid->cc, pcr);

				pkt = &pid->pkt_scr[0];
				outputPid = pid;
				break;
			}

			//	printf("i %d pid->pid 0x%04x, sidx %d, pkts_count %d\n", i, pid->pid, schedule_idx, pid->pkts_count);

			/* Find the next packet and check its scheduling time. */
			/* Make sure its scheduled to go out */
			/* Otherwise leave with item being NULL and a null packet will go out instead */
			if (pkt == NULL && pid->pkts_idx < pid->pkts_count) {
				pkt = &pid->pkts[ pid->pkts_idx * 188 ];
				if (pid->pkts_outputSTC[pid->pkts_idx] <= get_computed_stc(ctx)) {
					pid->pkts_idx++;
					outputPid = pid;
				} else {
					pkt = NULL; /* Send a null packet instead */
				}

				break;
			}
		}
	}

	if (!pkt) {
		/* Hmm, not time for PSIP or audio/video. Could be null packet time. */
		if (ctx->null_pkt_outputSTC < get_computed_stc(ctx)) {
			pkt = &ctx->null_pkt[0];
			ctx->null_pkt_outputSTC += ctx->ticks_per_outputts27MHz;
		}
	}

	if (pkt) {
		if (outputPid && outputPid->type == PID_VIDEO) {
			/* All video pids need to be rolled because we inject PCR 
			 * packet randomly into the schedule, messing up the pre-allocated CC's
			 */
			if (ltntstools_has_adaption(pkt)) {
				if (ltntstools_adaption_field_control(pkt) == 0x02 /* Adaption only */) {
					/* Don't roll the cc for adaption only packets. issue the last counter. */
					pkt[3] &= 0xf0;
					pkt[3] |= ((outputPid->ccRoller - 1) & 0x0f);
				}
			} else {
				pkt[3] &= 0xf0;
				pkt[3] |= (outputPid->ccRoller & 0x0f);
				outputPid->ccRoller++;
			}
		}

		/* Send a single PKT to the reframer */
		ltststools_reframer_write(ctx->reframer, pkt, 188);
		ctx->ts_packets_sent++;
	}
}

static void usage(const char *progname)
{
	printf("\nA demonstration tool to merge two SPTS input streams into a single MPTS.\n");
	printf("Highly experimental development. Not for use in any test or production environment.\n");
	printf("Many things are hardcoded and tuned for use in a developers single environment\n\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
               "           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -P 0xPID:0xSTREAMID\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("\n  Eg. %s -i 'udp://227.1.20.80:4002?buffer_size=2500000&overrun_nonfatal=1&fifo_size=50000000' -P 0x31:0xe0 -P 0x32:0xc0 \\\n", progname);
	printf("                     -i 'udp://227.1.20.80:4002?buffer_size=2500000&overrun_nonfatal=1&fifo_size=50000000' -P 0x31:0xe0 -P 0x32:0xc0\n");
	printf("\n  Eg. %s -v -B 50000000 -T sample.ts\n", progname);
	printf("\n");
}

int mpts(int argc, char *argv[])
{
	struct tool_ctx_s myctx, *ctx;
	ctx = &myctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->inputNr = -1;
	ctx->output_psip_idx = -1;
	ctx->schedule_entries = 4;
	ctx->null_pkt_outputSTC = get_computed_stc(ctx);

	ltntstools_generateNullPacket(&ctx->null_pkt[0]);

	ctx->reframer = ltntstools_reframer_alloc(ctx, 7 * 188, (ltntstools_reframer_callback)reframer_callback);

	/* Setup UDP socket for output */
    ctx->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ctx->addr.sin_family = AF_INET;
    ctx->addr.sin_port = htons(4900);
    inet_pton(AF_INET, "227.1.20.45", &ctx->addr.sin_addr);

	int ch;

	uint32_t pid;
	uint32_t streamId;

	while ((ch = getopt(argc, argv, "?hvi:P:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->inputNr++;
			ctx->streams[ctx->inputNr] = stream_alloc(ctx, optarg, ctx->inputNr);
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x:0x%x", &pid, &streamId) != 2) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			stream_add_pid(ctx->streams[ctx->inputNr], pid, pid + (0x100 * (ctx->inputNr +1)), streamId);
			break;
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->inputNr < 0) {
		usage(argv[0]);
		exit(1);
	}
	printf("inputNr: %d\n", ctx->inputNr);

	/* For the entire output mux, determine the number of tickets per TS packet */
	double bitrate_bps = TARGET_BITRATE;
	double packet_duration_sec = (double)(188.0 * 8.0) / bitrate_bps;
	double ticks_per_packet = packet_duration_sec * 27000000.0;
	ctx->ticks_per_outputts27MHz = ticks_per_packet;

	/* Mostly hardcoded. Buld a PAT object and we'll synthesize actial PAT/PMT packets from this. */
	ctx->pat = ltntstools_pat_alloc();
	struct ltntstools_pat_s *pat = ctx->pat;
	pat->transport_stream_id = 1;
	pat->version_number = 1;
	pat->current_next_indicator = 1;
	pat->program_count = 2;

	for (int i = 0; i <= ctx->inputNr; i++) {
		int prog = i + 1;
		pat->programs[i].program_number = prog;
		pat->programs[i].program_map_PID = 0x100 * prog;
		pat->programs[i].pmt.current_next_indicator = 1;
		pat->programs[i].pmt.PCR_PID = 0x31 + (0x100 * prog);
		pat->programs[i].pmt.program_number = prog;
		pat->programs[i].pmt.version_number = 1;
		pat->programs[i].pmt.stream_count = 2;
		pat->programs[i].pmt.streams[0].elementary_PID = 0x31 + (0x100 * prog);
		pat->programs[i].pmt.streams[0].stream_type    = 0x1b;
		pat->programs[i].pmt.streams[1].elementary_PID = 0x32 + (0x100 * prog);
		pat->programs[i].pmt.streams[1].stream_type    = 0x04;
		pat->programs[i].pmt.streams[1].stream_type    = 0x81; // AC3
	}

	/* Setup the output schedule to give each stream time in the packet scheduler. */
	ctx->schedule[0] = ctx->streams[0]->pids[0];
	ctx->schedule[1] = ctx->streams[0]->pids[1];
	ctx->schedule[2] = ctx->streams[1]->pids[0];
	ctx->schedule[3] = ctx->streams[1]->pids[1];

	/* Build a pid output schedule. Each time we iterate a need to output a packet,
	 * we process the threads in this order.
	 */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Main clock we use to drive the mux */
    clock_gettime(CLOCK_MONOTONIC, &ctx->next_time);

	/* Main loop.
	 * Build psip every second.
	 * output psip every second.
	 * Walk the schedule and find a packet on the pid
	 * If no packets in psip, or pid need to be output,
	 * send a null packet instead.
	 * Go to sleep for a while.
	 */
	int calls_per_sleep = 7;
	while (g_running) {

		/* N service calls per sleep, enough to fit a UDP frame. */
		for (int i = 0; i < calls_per_sleep; i++) {
			service(ctx);
		}

		/* Have a haba daba too time... sleep a while */
		ctx->next_time.tv_nsec += (PACKET_INTERVAL_NS * calls_per_sleep);
        while (ctx->next_time.tv_nsec >= 1000000000) {
            ctx->next_time.tv_nsec -= 1000000000;
            ctx->next_time.tv_sec += 1;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ctx->next_time, NULL);

	} /* g_running */

	ltntstools_pat_free(pat);
	ltntstools_reframer_free(ctx->reframer);
	close(ctx->sockfd);
	return 0;
}
