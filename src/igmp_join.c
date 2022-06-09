/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"

static int gRunning = 0;

struct tool_context_s
{
	char *iname;
	int verbose;
	int stopAfterSeconds;

#ifdef __linux__
	timer_t timerId;
#endif

	/* ffmpeg related */
	pthread_t ffmpeg_threadId;
	int ffmpeg_threadTerminate, ffmpeg_threadRunning, ffmpeg_threadTerminated;
	AVIOContext *puc;
};

static void *thread_packet_rx(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->ffmpeg_threadRunning = 1;
	ctx->ffmpeg_threadTerminate = 0;
	ctx->ffmpeg_threadTerminated = 0;

	pthread_detach(ctx->ffmpeg_threadId);

	unsigned char buf[7 * 188];

	while (!ctx->ffmpeg_threadTerminate) {
		int rlen = avio_read(ctx->puc, buf, sizeof(buf));
		if (ctx->verbose) {
			printf("source received %d bytes\n", rlen);
		}
		if ((rlen == -EAGAIN) || (rlen == -ETIMEDOUT)) {
			usleep(2 * 1000);
			continue;
		} else
		if (rlen < 0) {
			usleep(2 * 1000);
			gRunning = 0;
			/* General Error or end of stream. */
			continue;
		}

		/* Discard the packets */
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
	printf("Terminating due to -t condition\n");
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
	printf("A tool to issue IGMP joins on a specific multicast group and interface.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://234.1.1.1:4160?localaddr=172.16.0.67\n");
	printf("           172.16.0.67 is the IP addr where we'll issue a IGMP join\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
#ifdef __linux__
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
#endif
}

int igmp_join(int argc, char *argv[])
{
	int ret = 0;
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

	while ((ch = getopt(argc, argv, "?hi:vt:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->iname = optarg;
			break;
		case 'v':
			ctx->verbose++;
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

	if (ctx->iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	if (ctx->stopAfterSeconds) {
#ifdef __linux__
		terminate_after_seconds(ctx, ctx->stopAfterSeconds);
#endif
	}

	avformat_network_init();
	
	ret = avio_open2(&ctx->puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		ret = -1;
		goto no_output;
	}

	signal(SIGINT, signal_handler);
	gRunning = 1;

	pthread_create(&ctx->ffmpeg_threadId, 0, thread_packet_rx, ctx);

	printf("\nJoined %s\n", ctx->iname);
	printf("<CTRL-C> to exit\n");
	while (gRunning) {
		usleep(50 * 1000);
	}

	/* Shutdown ffmpeg */
	ctx->ffmpeg_threadTerminate = 1;
	while (!ctx->ffmpeg_threadTerminated)
		usleep(50 * 1000);

	avio_close(ctx->puc);

	ret = 0;

no_output:
	return ret;
}
