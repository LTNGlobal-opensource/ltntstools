/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "switcher-types.h"

int g_running = 1;
static void signal_handler(int signum)
{
	g_running = 0;
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
	struct output_stream_s *os = ctx->outputStream;
	struct pid_s *outputPid = NULL;

	/* Every 950ms print a PES queue size report */
	if (timesec_diff(ctx->next_time, ctx->last_q_report) >= 950) {
		ctx->last_q_report = ctx->next_time;

		struct timeval ts;
		gettimeofday(&ts, NULL);

		printf("%d.%06d: PES Queues/Size: ", (int)ts.tv_sec, (int)ts.tv_usec);
		for (int i = 0; i <= ctx->inputNr; i++) {
			input_stream_pes_q_report(ctx->streams[i]);
		}
		printf("\n");
	}

	/* Every 50ms generate new PAT/PMT service information */
	if (timesec_diff(ctx->next_time, os->last_psip) > 50) {
		/* Generate the PSIP multiple times a second, and schedule them for output. */
		output_generate_psip(os);
	}

	/* Try to ensure we have TS packets available for all input streams, all pids.  */
	for (int s = 0; s <= ctx->inputNr; s++) {
		input_stream_pes_to_ts(ctx->streams[s]);
	} /* For all input stream, ensure we have TS packets available. */

	/* Each iteration through, we output a single packet. If we don't have a packet
	 * in the schedule to send, then a NULL packet goes out.
	 * "Only one ping Mr Borodin, one ping."
	 */
	uint8_t *pkt = NULL;

	if (ctx->output_psip_idx > -1) {
		/* Its time to output a PSIP packet, select one. */

		pkt = &ctx->outputStream->psip_pkt[ ctx->output_psip_idx ][0];

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
				if (pid->pkts_outputSTC[pid->pkts_idx] <= output_get_computed_stc(ctx->outputStream)) {
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
		if (ctx->null_pkt_outputSTC < output_get_computed_stc(ctx->outputStream)) {
			pkt = &ctx->null_pkt[0];
			ctx->null_pkt_outputSTC += ctx->outputStream->ticks_per_outputts27MHz;
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
		output_write(ctx->outputStream, pkt, 188);
	}
}

static void usage(const char *progname)
{
	printf("\nA demonstration tool to seamless switch between two input SPTS, create a single MPTS, and rebase all the timing.\n");
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

int switcher_main(int argc, char *argv[])
{
	struct tool_ctx_s myctx, *ctx;
	ctx = &myctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->inputNr = -1;
	ctx->output_psip_idx = -1;
	ctx->schedule_entries = 4;

	ltntstools_generateNullPacket(&ctx->null_pkt[0]);

	if (output_alloc(ctx, &ctx->outputStream) < 0) {
		fprintf(stderr, "output alloc failed, aborting.\n");
		exit(1);
	}
	ctx->null_pkt_outputSTC = output_get_computed_stc(ctx->outputStream);

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
			ctx->streams[ctx->inputNr] = input_stream_alloc(ctx, optarg, ctx->inputNr);
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x:0x%x", &pid, &streamId) != 2) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			/* Add the input pid, changes its output pid to 0x100 + pidnr + input nr. */
			input_stream_add_pid(ctx->streams[ctx->inputNr], pid, pid + (0x100 * (ctx->inputNr +1)), streamId);
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
	 * Build psip multiple times every second.
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

		/* Have a haba daba doo time... sleep a while */
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
		input_stream_free(ctx->streams[i]);
	}

	output_free(ctx->outputStream);
	return 0;
}
