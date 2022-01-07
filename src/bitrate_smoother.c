/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

/*
 tstools_bitrate_smoother -i udp://127.0.0.1:4001?buffer_size=250000 \
                          -o udp://127.0.0.1:4002?pkt_size=1316 -b 20000000 -P 0x500
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <curses.h>
#include <inttypes.h>
#include <pthread.h>
#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "kbhit.h"

#define DEFAULT_FIFOSIZE 1048576
#define DEFAULT_TRAILERROW 18

static int gRunning = 0;

struct tool_context_s
{
	char *iname, *oname;
	int verbose;
	int stopAfterSeconds;

	struct ltntstools_stream_statistics_s i_stream, o_stream;
	void *smoother;

	pthread_t threadId;
	int trailerRow;
	int threadTerminate, threadRunning, threadTerminated;

#ifdef __linux__
	timer_t timerId;
#endif

	/* ffmpeg related */
	pthread_t ffmpeg_threadId;
	int ffmpeg_threadTerminate, ffmpeg_threadRunning, ffmpeg_threadTerminated;
	AVIOContext *i_puc;
	AVIOContext *o_puc;

	int bitrate_bps;
	int pcrPID;
};

static void *smoother_cb(void *userContext, unsigned char *buf, int byteCount)
{
	struct tool_context_s *ctx = userContext;

	for (int i = 0; i < byteCount; i += 188) {
		uint16_t pidnr = ltntstools_pid(buf + i);
		struct ltntstools_pid_statistics_s *pid = &ctx->o_stream.pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = ltntstools_continuity_counter(buf + i);
		if (ltntstools_isCCInError(buf + i, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
				char ts[256];
				time_t now = time(0);
				sprintf(ts, "%s", ctime(&now));
				ts[ strlen(ts) - 1] = 0;
				printf("%s: CC Error : pid %04x -- Got 0x%x wanted 0x%x\n", ts, pidnr, cc, (pid->lastCC + 1) & 0x0f);
				pid->ccErrors++;
			}
		}

		pid->lastCC = cc;

		if (ltntstools_tei_set(buf + i))
			pid->teiErrors++;

		if (ctx->verbose) {
			for (int i = 0; i < byteCount; i += 188) {
				for (int j = 0; j < 24; j++) {
					printf("%02x ", buf[i + j]);
					if (j == 3)
						printf("-- 0x%04x(%4d) -- ", pidnr, pidnr);
				}
				printf("\n");
			}
		}
	}


	avio_write(ctx->o_puc, buf, byteCount);

	return NULL;
}

static void *packet_cb(struct tool_context_s *ctx, unsigned char *buf, int byteCount)
{
	for (int i = 0; i < byteCount; i += 188) {
		uint16_t pidnr = ltntstools_pid(buf + i);
		struct ltntstools_pid_statistics_s *pid = &ctx->i_stream.pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = ltntstools_continuity_counter(buf + i);
		if (ltntstools_isCCInError(buf + i, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
				char ts[256];
				time_t now = time(0);
				sprintf(ts, "%s", ctime(&now));
				ts[ strlen(ts) - 1] = 0;
				printf("%s: CC Error : pid %04x -- Got 0x%x wanted 0x%x\n", ts, pidnr, cc, (pid->lastCC + 1) & 0x0f);
				pid->ccErrors++;
			}
		}

		pid->lastCC = cc;

		if (ltntstools_tei_set(buf + i))
			pid->teiErrors++;

		if (ctx->verbose) {
			for (int i = 0; i < byteCount; i += 188) {
				for (int j = 0; j < 24; j++) {
					printf("%02x ", buf[i + j]);
					if (j == 3)
						printf("-- 0x%04x(%4d) -- ", pidnr, pidnr);
				}
				printf("\n");
			}
		}
	}

	return 0;
}

static void *thread_packet_rx(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->ffmpeg_threadRunning = 1;
	ctx->ffmpeg_threadTerminate = 0;
	ctx->ffmpeg_threadTerminated = 0;

	pthread_detach(ctx->ffmpeg_threadId);

	unsigned char buf[7 * 188];

	while (!ctx->ffmpeg_threadTerminate) {
		int rlen = avio_read(ctx->i_puc, buf, sizeof(buf));
		if (ctx->verbose == 2) {
			printf("source received %d bytes\n", rlen);
		}
		if ((rlen == -EAGAIN) || (rlen == -ETIMEDOUT)) {
			usleep(1 * 1000);
			continue;
		} else
		if (rlen < 0) {
			usleep(1 * 1000);
			gRunning = 0;
			/* General Error or end of stream. */
			continue;
		}

		if (rlen > 0) 
			packet_cb(ctx, &buf[0], rlen);

		smoother_pcr_write(ctx->smoother, buf, sizeof(buf), NULL);
	}
	ctx->ffmpeg_threadTerminated = 1;

	pthread_exit(0);
	return 0;
}

static void signal_handler(int signum)
{
	gRunning = 0;
}

#ifdef __linux__
static void timer_thread(union sigval arg)
{
	signal_handler(0);
}

static void terminate_after_seconds(struct tool_context_s *ctx, int seconds)
{
	struct sigevent se;
	se.sigev_notify = SIGEV_THREAD;
	se.sigev_value.sival_ptr = &ctx->timerId;
	se.sigev_notify_function = timer_thread;
	se.sigev_notify_attributes = NULL;

	struct itimerspec ts;
	ts.it_value.tv_sec = seconds;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;

	int ret = timer_create(CLOCK_REALTIME, &se, &ctx->timerId);
	if (ret < 0) {
		fprintf(stderr, "Failed to create termination timer.\n");
		return;
	}

	ret = timer_settime(ctx->timerId, 0, &ts, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to start termination timer.\n");
		return;
	}
}
#endif

static void usage(const char *progname)
{
	printf("A tool to smooth input n*bps CBR bitrate to an output UDP stream.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://234.1.1.1:4160?localaddr=172.16.0.67\n");
	printf("           172.16.0.67 is the IP addr where we'll issue a IGMP join\n");
	printf("  -o <url> Eg: udp://234.1.1.1:4560\n");
	printf("  -P 0xnnnn PID containing the PCR\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -b bitrate (bps) that the input stream should match.\n");
	printf("  -h Display command line help.\n");
#ifdef __linux__
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
#endif
	printf("\n  Example:\n");
	printf("    tstools_bitrate_smoother -i 'udp://227.1.20.80:4002?localaddr=192.168.20.45&buffer_size=250000' \\\n");
	printf("      -o udp://227.1.20.45:4501?pkt_size=1316 -b 15000000 -P 0x31\n");
}

int bitrate_smoother(int argc, char *argv[])
{
	int ret = 0;
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

	while ((ch = getopt(argc, argv, "?hi:b:o:P:vt:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'b':
			ctx->bitrate_bps = atoi(optarg);
			break;
		case 'i':
			ctx->iname = optarg;
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'o':
			ctx->oname = optarg;
			break;
		case 'P':
                        if ((sscanf(optarg, "0x%x", &ctx->pcrPID) != 1) || (ctx->pcrPID > 0x1fff)) {
                                usage(argv[0]);
                                exit(1);
                        }
			break;
#ifdef __linux__
		case 't':
			ctx->stopAfterSeconds = atoi(optarg);
			break;
#endif
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (!ctx->bitrate_bps) {
		usage(argv[0]);
		fprintf(stderr, "\n-b is mandatory, aborting.\n\n");
		exit(1);
	}

	if (!ctx->pcrPID) {
		usage(argv[0]);
		fprintf(stderr, "\n-P is mandatory, aborting.\n\n");
		exit(1);
	}

	if (ctx->iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory, aborting.\n\n");
		exit(1);
	}

	if (ctx->oname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-o is mandatory, aborting.\n\n");
		exit(1);
	}

	if (ctx->stopAfterSeconds) {
#ifdef __linux__
		terminate_after_seconds(ctx, ctx->stopAfterSeconds);
#endif
	}

	avformat_network_init();
	
	ret = avio_open2(&ctx->i_puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		ret = -1;
		goto no_output;
	}

	ret = avio_open2(&ctx->o_puc, ctx->oname, AVIO_FLAG_WRITE | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-o syntax error\n");
		ret = -1;
		goto no_output;
	}

	ret = smoother_pcr_alloc(&ctx->smoother, ctx, (smoother_pcr_output_callback)smoother_cb,
		5000, 1316, ctx->pcrPID, ctx->bitrate_bps);

	/* Preallocate enough throughput measures for approx a 40mbit stream */
	signal(SIGINT, signal_handler);
	gRunning = 1;

	pthread_create(&ctx->ffmpeg_threadId, 0, thread_packet_rx, ctx);

	signal(SIGINT, signal_handler);
	while (gRunning) {
		usleep(50 * 1000);
	}

	/* Shutdown ffmpeg */
	ctx->ffmpeg_threadTerminate = 1;
	while (!ctx->ffmpeg_threadTerminated)
		usleep(50 * 1000);

	avio_close(ctx->i_puc);
	avio_close(ctx->o_puc);

	smoother_pcr_free(ctx->smoother);

	ret = 0;

	if (ctx->iname)
		printf("\nInput from %s\n", ctx->iname);
	if (ctx->oname)
		printf("Output  to %s\n", ctx->oname);

	int64_t errCount = 0;

	printf("\nI: PID   PID     PacketCount   CCErrors  TEIErrors\n");
	printf("----------------------------  --------- ----------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->i_stream.pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n", i, i,
				ctx->i_stream.pids[i].packetCount,
				ctx->i_stream.pids[i].ccErrors,
				ctx->i_stream.pids[i].teiErrors);
			errCount += ctx->i_stream.pids[i].ccErrors;
		}
	}

	printf("O: PID   PID     PacketCount   CCErrors  TEIErrors\n");
	printf("----------------------------  --------- ----------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->o_stream.pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n", i, i,
				ctx->o_stream.pids[i].packetCount,
				ctx->o_stream.pids[i].ccErrors,
				ctx->o_stream.pids[i].teiErrors);
			errCount += ctx->o_stream.pids[i].ccErrors;
		}
	}

	ret = 0;

no_output:
	return ret;
}
