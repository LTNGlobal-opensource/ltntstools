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
#include "klbitstream_readwriter.h"

#include "switcher-types.h"

int g_running = 1;
static struct tool_ctx_s g_ctx;

static void signal_handler(int signr)
{
	struct tool_ctx_s *ctx = &g_ctx;

	switch(signr) {
	case SIGINT:
		g_running = 0;
		break;
	case SIGUSR1:
		tprintf("SIGUSR1 - flushing inputs\n");
		ctx->flushInput = 1;
		break;
	case SIGUSR2:
		tprintf("SIGUSR2\n");
		break;
	default:
		printf("signr %d\n", signr);
	}
}

void tprintf(const char *fmt, ...)
{
	struct timeval ts;
	gettimeofday(&ts, NULL);

	printf("%d.%06d: ", (int)ts.tv_sec, (int)ts.tv_usec);

    /* Handle variable arguments */
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);	
}

/* Place the input stream into the active schedule */
static void schedule_stream(struct tool_ctx_s *ctx, struct input_stream_s *is)
{
	pthread_mutex_lock(&ctx->schedule_lock);
	ctx->schedule[0] = is->pids[0];
	ctx->schedule[1] = is->pids[1];
	pthread_mutex_unlock(&ctx->schedule_lock);
}

static void service(struct tool_ctx_s *ctx)
{
	struct output_stream_s *os = ctx->outputStream;
	struct pid_s *outputPid = NULL;
	struct input_stream_s *stream = ctx->input_streams[ ctx->activeInputNr ];

	if (libltntstools_timespec_diff_ms(ctx->next_time, ctx->last_compatability_check) >= 15000) {
		ctx->last_compatability_check = ctx->next_time;
		if (input_stream_models_compatible(ctx->input_streams[0], ctx->input_streams[1]) != 1) {
			tprintf("Model compatability issue - Inducing stall because I want you to deal with it. Expect IAT issue\n");
			usleep(1000 * 1000);
			return;
		}
	}

	/* Periodically, every 5 seconds, remove PES content from queues older than N seconds */
	if (libltntstools_timespec_diff_ms(ctx->next_time, ctx->last_q_purge) >= 5000) {
		ctx->last_q_purge = ctx->next_time;
		for (int i = 0; i <= ctx->inputNr; i++) {
			input_stream_prune_history(ctx->input_streams[i]);
		}
	}

	/* Periodically, every 15 seconds, report codec statistics */
	if (libltntstools_timespec_diff_ms(ctx->next_time, ctx->last_codec_report) >= 15000) {
		ctx->last_codec_report = ctx->next_time;
		for (int i = 0; i <= ctx->inputNr; i++) {
			input_stream_show_codec_stats(ctx->input_streams[i]);
		}
		for (int i = 0; i <= ctx->inputNr; i++) {
			tprintf("input  stream[%d] %5.2f mbps, %" PRIu64 " CC errors, %s\n",
				ctx->input_streams[i]->nr,
				ltntstools_pid_stats_stream_get_mbps(ctx->input_streams[i]->libstats),
				ltntstools_pid_stats_stream_get_cc_errors(ctx->input_streams[i]->libstats),
				ctx->input_streams[i]->iname);
		}
		tprintf("output stream[0] %5.2f mbps, %" PRIu64 " CC errors, %s\n",
			ltntstools_pid_stats_stream_get_mbps(ctx->outputStream->libstats),
			ltntstools_pid_stats_stream_get_cc_errors(ctx->outputStream->libstats),
			ctx->outputStream->oname);
	}

	/* Periodically, every 950ms, show the size of each stream and pid Q to console. */
	if (libltntstools_timespec_diff_ms(ctx->next_time, ctx->last_q_report) >= 950) {
		ctx->last_q_report = ctx->next_time;

		struct timeval ts;
		gettimeofday(&ts, NULL);

		tprintf("PES Queues/Size: ");
		for (int i = 0; i <= ctx->inputNr; i++) {
			struct input_stream_s *stream = ctx->input_streams[i];
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

	/* Periodically, every 50ms, Generate the PSIP and schedule for output. */
	if (libltntstools_timespec_diff_ms(ctx->next_time, ctx->last_psip) > 50) {
		ctx->last_psip = ctx->next_time;

		if (stream->smpat) {
			ltntstools_pat_create_packet_ts(stream->smpat, ctx->psip_cc[0]++, &ctx->psip_pkt[0][0], 188);
			ltntstools_pmt_create_packet_ts(&stream->smpat->programs[0].pmt, stream->smpat->programs[0].program_map_PID, ctx->psip_cc[1]++, &ctx->psip_pkt[1][0], 188);
			ctx->output_psip_idx = 0; /* Throw a flag, start outputting the PSIP from packet 0 */
		}

	}

	/* Try to ensure we have TS packets available for all input streams, all pids.  */
	for (int p = 0; p < stream->pidCount; p++) { /* For each input pid */
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

			if (ctx->flushInput == 1) {
				input_stream_pid_set_state(pid, PS_SCHEDULE_EOL);
				tprintf("stream[%d].pid 0x%04x WENT EOL\n", stream->nr, pid->pid);
			} else {
				input_stream_pid_set_state(pid, PS_SCHEDULE_NEXT_PACKET);
			}
		}

		/* If this pid doesn't have any packets queued.... convert the next pes into TS */
		if (input_stream_pid_get_state(pid) == PS_SCHEDULE_NEXT_PACKET && pid->pkts_count == 0) {
			/* Get more ts packets */

			pthread_mutex_lock(&pid->peslistlock);
			struct pes_item_s *e = NULL, *next = NULL;
			xorg_list_for_each_entry_safe(e, next, &pid->peslist, list) {
				if (e->outputSTC < output_get_computed_stc(os)) {
					item = e;
					xorg_list_del(&e->list);
					pid->peslistcount--;
					break;
				}
			}
			pthread_mutex_unlock(&pid->peslistlock);

			if (!item) {
				/* Nothing to output */
				continue;
			}

#if 0
			printf("About to schedule: ");
			pes_item_dump(item, 0);
#endif

			/* Adjust the PES prior to packetization, apply clock adjustment
			 * so our timing model remains consistent rehrdless of input stream.
			 */
			if (pid->performClockAdjustmentPTS && ltn_pes_packet_has_PTS(item->pes)) {
				pid->clockAdjustmentPTS = (pid->lastOutputPTS + pid->lastOutputPTSDelta) - item->pes->PTS;

				printf("decoder(pts) pid 0x%04x wanted PTS %" PRIi64 " we're offering %" PRIi64 ", new adjust %" PRIi64 "\n",
					pid->pid,
					pid->lastOutputPTS + pid->lastOutputPTSDelta,
					item->pes->PTS,
					pid->clockAdjustmentPTS);

				pid->performClockAdjustmentPTS = 0;

			}

			if (pid->performClockAdjustmentDTS && item->pes->DTS) {

				pid->clockAdjustmentDTS = (pid->lastOutputDTS + pid->lastOutputDTSDelta) - item->pes->DTS;

				printf("decoder(dts) pid 0x%04x wanted DTS %" PRIi64 " we're offering %" PRIi64 ", new adjust %" PRIi64 "\n",
					pid->pid,
					pid->lastOutputDTS + pid->lastOutputDTSDelta,
					item->pes->DTS,
					pid->clockAdjustmentDTS);

				pid->performClockAdjustmentDTS = 0;

			}

			/* Go ahead and modify the PES, we'll transmit this to network. */
			if (ltn_pes_packet_has_PTS(item->pes)) {
				item->pes->PTS += pid->clockAdjustmentPTS; /* TODO: Deal with wrapping */
			}
			if (ltn_pes_packet_has_DTS(item->pes)) {
				item->pes->DTS += pid->clockAdjustmentDTS; /* TODO: Deal with wrapping */
			}

			if (pid->lastOutputPTS) {
				pid->lastOutputPTSDelta = item->pes->PTS - pid->lastOutputPTS;
			}
			if (pid->lastOutputDTS) {
				pid->lastOutputDTSDelta = item->pes->DTS - pid->lastOutputDTS;
//				if (pid->pid == 0x101 && stream->nr == 0)
//					printf("DTS delta %" PRIi64 "\n", pid->lastOutputDTSDelta);
			}

			if (ltn_pes_packet_has_PTS(item->pes)) {
				pid->lastOutputPTS = item->pes->PTS;
			}

			if (item->pes->DTS) {
				pid->lastOutputDTS = item->pes->DTS;
			}

			/* Create a bistream object, needed for PES packing. */
			struct klbs_context_s lbs;
			klbs_init(&lbs);
			int bslen = ((item->pes->rawBufferLengthBytes / 4096) + 1) * 4096;
			uint8_t *buf = malloc(bslen);

			if (buf) {
				klbs_write_set_buffer(&lbs, buf, bslen);
				klbs_read_set_buffer(&lbs, buf, bslen);

				/* Pack the modified PES */
				unsigned int bitsPacked = ltn_pes_packet_pack(item->pes, &lbs);
				unsigned int bytesPacked = bitsPacked / 8;

				if (bytesPacked == item->pes->rawBufferLengthBytes) {

					int random_access_indicator = 0;
					int elementary_stream_priority_indicator = 0;

					if (pid->type == PID_AUDIO) {
						random_access_indicator = 1;
						elementary_stream_priority_indicator = 1;
					}

					if (ltntstools_ts_packetizer_with_pcr(buf, bytesPacked, &pid->pkts, &pid->pkts_count,
						188, &pid->cc, pid->outputPidNr, -1, random_access_indicator, elementary_stream_priority_indicator) < 0) {
						printf("Err packetizing to TS\n");
						exit(1);
					}
				} else {
					tprintf("PES packing error, needed to pack %d bytes, instead packed %d. Magic smoke escaping? Dropped PES.\n",
						item->pes->rawBufferLengthBytes, bytesPacked);
				}

				free(buf);
				buf = NULL;
			}

			if (pid->pkts_count < 1) {
				tprintf("Send pes for packetization and nothing came out, something went wrong\n");
				exit(1);
			}
			if (ctx->verbose > 3) {
				tprintf("Created %4d ts packets for pid 0x%04x\n", pid->pkts_count, pid->outputPidNr);
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

			pes_item_free(item);
		}
	}

	/* Each iteration through, we output a single packet. If we don't have a packet
		* in the schedule to send, then a NULL packet goes out.
		* "Only one ping Mr Borodin, one ping."
		*/

	uint8_t *pkt = NULL;

	if (ctx->output_psip_idx > -1) {
		/* We're flagged to output a PSIP packet, select next. */
		pkt = &ctx->psip_pkt[ ctx->output_psip_idx ][0];

		if (++ctx->output_psip_idx == 2) {
			ctx->output_psip_idx = -1; /* End of PSIP packet list */
		}
	}

	if (!pkt) {
		/* Output a regular codec stream packet, select one.
		 * Using an input schedule forces pid interleaving.
		 */
		pthread_mutex_lock(&ctx->schedule_lock);
		for (int i = 0; i < ctx->schedule_entries; i++) {
			ctx->schedule_idx = (ctx->schedule_idx + 1) % ctx->schedule_entries;
			struct pid_s *pid = ctx->schedule[ctx->schedule_idx];

			if (pid->type == PID_VIDEO && libltntstools_timespec_diff_ms(ctx->next_time, pid->last_pcr_output) >= 30) {
				/* Generate the PSIP multiple times a second, and schedule them for output. */
				pid->last_pcr_output = ctx->next_time;

				int64_t pcr;
#if 1
				pcr = output_get_computed_stc(os);
#else
				ltntstools_bitrate_calculator_query_stc(pid->stream->libstats, &pcr);
#endif
				pcr -= (27000 * 800); /* The PCR we're going to output is 800ms in the past. This keeps the PTS always ahead of it. */
				ltntstools_generatePCROnlyPacket(&pid->pkt_scr[0], sizeof(pid->pkt_scr), pid->outputPidNr, &pid->cc, pcr);

				pkt = &pid->pkt_scr[0];
				outputPid = pid;
				break;
			}

			/* Find the next packet and check its scheduling time. */
			/* Make sure its scheduled to go out */
			/* Otherwise leave with item being NULL and a null packet will go out instead */
			if (pkt == NULL && input_stream_pid_get_state(pid) == PS_SCHEDULE_NEXT_PACKET && pid->pkts_idx < pid->pkts_count) {
				if (pid->pkts_outputSTC[pid->pkts_idx] <= output_get_computed_stc(os)) {
					pkt = &pid->pkts[ pid->pkts_idx * 188 ];
					pid->pkts_idx++;
					outputPid = pid;
				} else {
					pkt = NULL; /* Send a null packet instead */
				}

				break;
			}
		}
		pthread_mutex_unlock(&ctx->schedule_lock);

	}

	if (!pkt) {
		/* Hmm, it's not time for PSIP or audio/video. Could be null packet time. */
		pkt = &os->null_pkt[0];
	}

	if (pkt) {
		if (outputPid && outputPid->type == PID_VIDEO) {
			/* All video pids need to be rolled because we inject PCR 
			 * packet randomly into the schedule, messing up the pre-allocated CC's
			 */
			if (ltntstools_has_adaption(pkt) && ltntstools_adaption_field_control(pkt) == 0x02 /* Adaption only */) {
				/* Don't roll the cc for adaption only packets. issue the last counter. */
				pkt[3] &= 0xf0;
				pkt[3] |= ((outputPid->ccRoller - 1) & 0x0f);
			} else {
				pkt[3] &= 0xf0;
				pkt[3] |= (outputPid->ccRoller & 0x0f);
				outputPid->ccRoller++;
			}
		}

		/* Send a single PKT to the reframer */
		ltststools_reframer_write(ctx->outputStream->reframer, pkt, 188);
		os->ts_packets_sent++;
	}

	/* if we're flushing and all pids are in a EOL state... adjust the schedule */
	if (ctx->flushInput) {

		/* Count the number of pids in EOL state */
		int eolCount = 0;
		for (int p = 0; p < stream->pidCount; p++) { /* For each input pid */
			struct pid_s *pid = stream->pids[p];
			if (input_stream_pid_get_state(pid) == PS_SCHEDULE_EOL) {
				tprintf("stream[%d].pid 0x%04x EOL\n", stream->nr, pid->pid);
				eolCount++;
			}
		}

		/* When all the pids are in the EOL state */
		if (eolCount == stream->pidCount) {
			tprintf("stream[%d] all pids are flushed, preparing for schedule adjustment\n", stream->nr);

			if (ctx->insert1FFESCROnSwitch) {
				/* Tell our external debug tools (clock inspector) the pids are EOL, send a cheeky PCR on an unused pid. */
				uint8_t pkt[188];
				uint8_t cc = 0;
				ltntstools_generatePCROnlyPacket(&pkt[0], sizeof(pkt), 0x1ffe, &cc, 0);
				ltststools_reframer_write(ctx->outputStream->reframer, pkt, 188);
				os->ts_packets_sent++;
			}

			/* compute the new timing bias for the input PES, to retain the output constant timing */
			struct input_stream_s *streamPrimary = ctx->input_streams[ ctx->activeInputNr ];
			struct input_stream_s *streamBackup  = ctx->input_streams[ (~ctx->activeInputNr) & 1 ];

			tprintf("Timing dump of Primary and backup streams, pcr is %" PRIi64 "\n",
				output_get_computed_stc(os));
			input_stream_timing_dump(streamPrimary);
			input_stream_timing_dump(streamBackup);
			tprintf("Timing dump complete\n");
			for (int p = 0; p < streamPrimary->pidCount; p++) {
				struct pid_s *pidPrimary = stream->pids[p];
				struct pid_s *pidBackup = input_stream_pid_lookup(pidPrimary, streamBackup);

				pidPrimary->clockAdjustmentPTS = 0;
				pidPrimary->clockAdjustmentDTS = 0;
				pidPrimary->performClockAdjustmentPTS = 0;
				pidPrimary->performClockAdjustmentDTS = 0;
				pidBackup->cc = pidPrimary->cc;
				pidBackup->ccRoller = pidPrimary->ccRoller;
				pidBackup->clockAdjustmentPTS = 0;
				pidBackup->clockAdjustmentDTS = 0;
				pidBackup->performClockAdjustmentPTS = 1;
				pidBackup->performClockAdjustmentDTS = 1;
				pidBackup->lastOutputPTS = pidPrimary->lastOutputPTS;
				pidBackup->lastOutputDTS = pidPrimary->lastOutputDTS;
				pidBackup->lastOutputPTSDelta = pidPrimary->lastOutputPTSDelta;
				pidBackup->lastOutputDTSDelta = pidPrimary->lastOutputDTSDelta;
			}

			/* adjust the schedule, start outputting payload from the alternate stream */
			/* Toggle the active input. */
			ctx->activeInputNr = (~ctx->activeInputNr) & 1;
			stream = ctx->input_streams[ctx->activeInputNr ];
			schedule_stream(ctx, stream);
			tprintf("stream[%d] became active input\n", stream->nr);

			/* Walk the active input pes queues, remove everything up to the next iframe */
			if (input_stream_flush_to_transition_point(stream) < 0) {
				tprintf("error flushing stream, ignoring\n");
			}

			for (int p = 0; p < stream->pidCount; p++) { /* For each input pid */
				struct pid_s *pid = stream->pids[p];
				input_stream_pid_set_state(pid, PS_SCHEDULE_NEXT_PACKET);
				tprintf("stream[%d].pid 0x%04x SCHEDULED\n", stream->nr, pid->pid);
			}
			ctx->flushInput = 0;
		}
	} /* if (ctx->flushInput) */

}

static void usage(const char *progname)
{
	printf("\nA tool that switches between two SPTS input streams, outputting a clean and consistent output stream.\n");
	printf("Highly experimental development. Not for use in any test or production environment.\n");
	printf("Many things are hardcoded and tuned for use in a developers single environment\n\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
               "           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -o <url> Eg: udp|rtp://234.1.1.1:4560?pkt_size=1316\n");
	printf("  -D <filename> Test function, exercises ffmpeg's demux for developer use. (don't use)\n");
	printf("  -P 0xPID:0xSTREAMID (pass this immediate after the -i url input)\n");
	printf("  -T create input[01].ts and output.ts recordings (debug feature)\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -Z Insert a dummy PCR on pid 0x1ffe immediately before the stream switch\n");
	printf("\n  Eg. %s \\\n", progname);
	printf("              -i udp://227.1.20.80:4001 -P 0x31:0xe0 -P 0x32:0xc0 \\\n");
	printf("              -i udp://227.1.20.82:4001 -P 0x31:0xe0 -P 0x32:0xc0 \\\n");
	printf("              -o udp://227.1.20.80:4002?pkt_size=1316\n");
	printf("\n");
}

int switcher_main(int argc, char *argv[])
{
	struct tool_ctx_s *ctx = &g_ctx;
	memset(ctx, 0, sizeof(*ctx));

	ctx->inputNr = -1;
	ctx->activeInputNr = 0;
	ctx->output_psip_idx = -1;
	ctx->schedule_entries = 2;
	pthread_mutex_init(&ctx->schedule_lock, NULL);

	int ch;

	uint32_t pid;
	uint32_t streamId;

	while ((ch = getopt(argc, argv, "?D:hvi:o:P:RTZ")) != -1) {
		switch (ch) {
		case 'D':
			return ffmpeg_demux_test(optarg);
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->inputNr++;
			ctx->input_streams[ctx->inputNr] = input_stream_alloc(ctx, optarg, ctx->inputNr);
			break;
		case 'o':
			ctx->outputStream = output_stream_alloc(ctx, optarg);
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x:0x%x", &pid, &streamId) != 2) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			input_stream_pid_add(ctx->input_streams[ctx->inputNr], pid, pid, streamId);
			break;
		case 'R':
			ctx->createTSRecordings = 1;
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'Z':
			ctx->insert1FFESCROnSwitch = 1;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->inputNr < 0) {
		usage(argv[0]);
		fprintf(stderr, "-i missing or illegal\n");
		exit(1);
	}
	tprintf("Number of Inputs: %d\n", ctx->inputNr + 1);

	if (ctx->outputStream == NULL) {
		usage(argv[0]);
		fprintf(stderr, "-o missing or illegal\n");
		exit(1);
	}

	/* Setup the output schedule to give each stream time in the packet scheduler. */
	schedule_stream(ctx, ctx->input_streams[0]);

	/* Build a pid output schedule. Each time we iterate a need to output a packet,
	 * we process the threads in this order.
	 */
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);

	/* Main clock we use to drive the mux */
    clock_gettime(CLOCK_MONOTONIC, &ctx->next_time);

	ctx->last_q_purge = ctx->next_time;
	ctx->last_psip = ctx->next_time;
	ctx->last_q_report = ctx->next_time;
	ctx->last_codec_report = ctx->next_time;
	ctx->last_compatability_check = ctx->next_time;

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
#ifdef __linux__
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ctx->next_time, NULL);
#endif
#ifdef __APPLE__
        nanosleep(&ctx->next_time, NULL);
#endif

	} /* g_running */

	for (int i = 0; i <= ctx->inputNr; i++) {
		input_stream_free(ctx->input_streams[i]);
	}

	if (ctx->outputStream) {
		output_stream_free(ctx->outputStream);
		ctx->outputStream = NULL;
	}

	return 0;
}
