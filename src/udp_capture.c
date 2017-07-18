/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <curses.h>
#include <inttypes.h>
#include <pthread.h>
#include "udp.h"
#include "url.h"
#include "pids.h"
#include "ffmpeg-includes.h"

#define DEFAULT_FIFOSIZE 1048576
#define DEFAULT_TRAILERROW 18

static int gRunning = 0;

struct tool_context_s
{
	char *iname;
	int verbose;

	FILE *ofh;

	uint64_t bytesWritten;
	uint64_t bytesWrittenCurrent;
	time_t bytesWrittenTime;

	struct stream_statistics_s stream;

	int monitor;
	pthread_t threadId;
	int trailerRow;
	int threadTerminate, threadRunning, threadTerminated;

	/* ffmpeg related */
	pthread_t ffmpeg_threadId;
	int ffmpeg_threadTerminate, ffmpeg_threadRunning, ffmpeg_threadTerminated;
	URLContext *puc;
};

static void *packet_cb(struct tool_context_s *ctx, unsigned char *buf, int byteCount)
{
	if (ctx->ofh) {
		size_t wlen = fwrite(buf, 1, byteCount, ctx->ofh);

		if (wlen != byteCount) {
			fprintf(stderr, "Warning: unable to write output\n");
		}
	}

	time_t now;
	time(&now);

	if (now != ctx->bytesWrittenTime) {
		ctx->bytesWrittenTime = now;
		ctx->bytesWritten = ctx->bytesWrittenCurrent;
		ctx->bytesWrittenCurrent = 0;
	}

	for (int i = 0; i < byteCount; i += 188) {
		uint16_t pidnr = getPID(buf + i);
		struct pid_statistics_s *pid = &ctx->stream.pids[pidnr];

		ctx->bytesWrittenCurrent += 188;

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = getCC(buf + i);
		if (isCCInError(buf + i, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
printf("pid %04x Got %x wanted %x BAD\n", pidnr, cc, (pid->lastCC + 1) & 0x0f);
				pid->ccErrors++;
			}
		}

		pid->lastCC = cc;

		if (isTEI(buf + i))
			pid->teiErrors++;

		if (ctx->verbose) {
			for (int i = 0; i < byteCount; i += 188) {
				for (int j = 0; j < 16; j++) {
					printf("%02x ", buf[i + j]);
					if (j == 3)
						printf("-- 0x%04x(%d) -- ", pidnr, pidnr);
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

	unsigned char buf[7 * 188];

	while (!ctx->ffmpeg_threadTerminate) {
		int rlen = ffurl_read(ctx->puc, buf, sizeof(buf));
		if (ctx->verbose == 2) {
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

		for (int i = 0; i < rlen; i += 188) {
			packet_cb(ctx, &buf[i], 188);			
		}

	}
	ctx->ffmpeg_threadTerminated = 1;
	return 0;
}

static void *thread_func(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->threadRunning = 1;
	ctx->threadTerminate = 0;
	ctx->threadTerminated = 0;
	ctx->trailerRow = DEFAULT_TRAILERROW;

	noecho();
	curs_set(0);
	start_color();
	init_pair(1, COLOR_WHITE, COLOR_BLUE);
	init_pair(2, COLOR_CYAN, COLOR_BLACK);
	init_pair(3, COLOR_RED, COLOR_BLACK);

	while (!ctx->threadTerminate) {

		time_t now;
		time(&now);

		clear();

		char title_a[160], title_b[160], title_c[160];
		sprintf(title_a, "%s", ctx->iname);
		sprintf(title_c, "%2.2f Mb/s", ((double)ctx->bytesWritten * 8) / 1000000.0);
		int blen = 75 - (strlen(title_a) + strlen(title_c));
		memset(title_b, 0x20, sizeof(title_b));
		title_b[blen] = 0;

		attron(COLOR_PAIR(1));
		mvprintw( 0, 0, "%s%s%s", title_a, title_b, title_c);
		mvprintw( 1, 0, "-- PID ---- PACKETS - Disc/Count -------- TEI                              ");
		attroff(COLOR_PAIR(1));

		int pidcnt = 0;
		for (int i = 0; i < MAX_PID; i++) {
			struct pid_statistics_s *pid = &ctx->stream.pids[i];
			if (!pid->enabled)
				continue;

			if (pid->ccErrors)
                                attron(COLOR_PAIR(3));

                        mvprintw(pidcnt + 2, 0, "0x%04x %12lld %12lld %12lld\n",
                                i, pid->packetCount, pid->ccErrors, pid->teiErrors
                        );

			if (pid->ccErrors)
                                attroff(COLOR_PAIR(3));
		
			pidcnt++;
		}
		ctx->trailerRow = pidcnt + 2;

		attron(COLOR_PAIR(2));
		mvprintw(ctx->trailerRow, 0, "q)uit r)eset");
		attroff(COLOR_PAIR(2));

		char tail_a[160], tail_b[160], tail_c[160];
		memset(tail_b, '-', sizeof(tail_b));
		sprintf(tail_a, "TSTOOLS_UDP_CAPTURE");
		sprintf(tail_c, "%s", ctime(&now));
		blen = 76 - (strlen(tail_a) + strlen(tail_c));
		memset(tail_b, 0x20, sizeof(tail_b));
		tail_b[blen] = 0;

		attron(COLOR_PAIR(1));
		mvprintw(ctx->trailerRow + 1, 0, "%s%s%s", tail_a, tail_b, tail_c);
		attroff(COLOR_PAIR(1));

                refresh();

		usleep(100 * 1000);
	}
	ctx->threadTerminated = 1;

	return 0;
}

static void signal_handler(int signum)
{
	gRunning = 0;
}

static void usage(const char *progname)
{
	printf("A tool to capture ISO13818 TS packet from the UDP network.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://234.1.1.1:5000?ifname=eno1\n");
	printf("  -o <output filename> (optional)\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -M Display an interactive console with stats.\n");
}

int udp_capture(int argc, char *argv[])
{
	int ret = 0;
	int ch;
	char *oname = NULL;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

	while ((ch = getopt(argc, argv, "?hi:o:vM")) != -1) {
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
		case 'M':
			ctx->monitor = 1;
			break;
		case 'o':
			oname = optarg;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->iname == NULL) {
		fprintf(stderr, "-i is mandatory.\n");
		exit(1);
	}

	avformat_network_init();
	
	ret = ffurl_open(&ctx->puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		ret = -1;
		goto no_output;
	}

	if (oname) {
		ctx->ofh = fopen(oname, "wb");
		if (!ctx->ofh) {
			fprintf(stderr, "Problem opening output file, aborting.\n");
			ret = -1;
			goto no_output;
		}
	}

	signal(SIGINT, signal_handler);
	gRunning = 1;

	if (ctx->monitor) {
		initscr();
		pthread_create(&ctx->threadId, 0, thread_func, ctx);
	}

	pthread_create(&ctx->ffmpeg_threadId, 0, thread_packet_rx, ctx);

	while (gRunning) {
		int ch = getch();
		if (ch == 'q')
			break;
		if (ch == 'r') {
			for (int i = 0; i < MAX_PID; i++) {
				struct pid_statistics_s *pid = &ctx->stream.pids[i];
				if (!pid->enabled)
					continue;
				pid->ccErrors = 0;
				pid->teiErrors = 0;
				pid->packetCount = 0;
				pid->enabled = 0;
			}
		}

		usleep(50 * 1000);
	}
	ffurl_shutdown(ctx->puc, 0);

	/* Shutdown ffmpeg */
	ctx->ffmpeg_threadTerminate = 1;
	while (!ctx->ffmpeg_threadTerminated)
		usleep(50 * 1000);

	if (ctx->monitor) {
		ctx->threadTerminate = 1;
		while (!ctx->threadTerminated)
			usleep(50 * 1000);

		endwin();
	}

	ret = 0;

	printf("\nWrote %" PRIu64 " bytes to %s\n", ctx->bytesWritten, oname);

	printf("   PID    PacketCount   CCErrors  TEIErrors\n");
	printf("---------------------- --------- ----------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->stream.pids[i].enabled) {
			printf("0x%04x %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n", i,
				ctx->stream.pids[i].packetCount,
				ctx->stream.pids[i].ccErrors,
				ctx->stream.pids[i].teiErrors);
		}
	}

	if (ctx->ofh)
		fclose(ctx->ofh);

no_output:
	return ret;
}
