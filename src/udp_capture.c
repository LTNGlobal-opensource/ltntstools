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

#define DEFAULT_FIFOSIZE 1048576
#define DEFAULT_TRAILERROW 18

static int gRunning = 0;

struct tool_context_s
{
	struct iso13818_udp_receiver_s *udprx;
	struct url_opts_s *url;
	char *iname;
	int verbose;

	FILE *ofh;

	uint64_t bytesWritten;

	struct stream_statistics_s stream;

	int monitor;
	pthread_t threadId;
	int trailerRow;
	int threadTerminate, threadRunning, threadTerminated;
};

static void *packet_cb(struct tool_context_s *ctx, unsigned char *buf, int byteCount)
{
	size_t wlen = fwrite(buf, 1, byteCount, ctx->ofh);
	ctx->bytesWritten += wlen;

	if (wlen != byteCount) {
		fprintf(stderr, "Warning: unable to write output\n");
	}

	for (int i = 0; i < byteCount; i += 188) {
		uint16_t pidnr = getPID(buf + i);
		struct pid_statistics_s *pid = &ctx->stream.pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = getCC(buf + i);
		if (((pid->lastCC + 1) & 0x0f) != cc) {
			if (pid->packetCount > 1)
				pid->ccErrors++;
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
		sprintf(title_c, "(C) LiveTimeNet, Inc.");
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
	printf("  -o <output filename>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -M Display an interactive console with stats.\n");
}

int udp_capture(int argc, char *argv[])
{
	int ret = 0;
	int ch;
	char *oname = NULL;
	int fifosize = DEFAULT_FIFOSIZE;

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
			if (url_parse(optarg, &ctx->url) < 0) {
				fprintf(stderr, "Problem parsing url, aborting.\n");
				exit(1);
			}
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
	if (oname == NULL) {
		fprintf(stderr, "-o is mandatory.\n");
		exit(1);
	}

	ctx->ofh = fopen(oname, "wb");
	if (!ctx->ofh) {
		fprintf(stderr, "Problem opening output file, aborting.\n");
		ret = -1;
		goto no_output;
	}

	if (ctx->url->has_fifosize)
		fifosize = ctx->url->fifosize;

	ret = iso13818_udp_receiver_alloc(&ctx->udprx, fifosize, ctx->url->hostname, ctx->url->port,
		(tsudp_receiver_callback)packet_cb, ctx, 0);
	if (ret < 0) {
		fprintf(stderr, "Problem allocating the URL receiver, aborting.\n");
		ret = -1;
		goto no_udp;
	}

	if (ctx->url->has_ifname)
		iso13818_udp_receiver_join_multicast(ctx->udprx, ctx->url->ifname);

	ret = iso13818_udp_receiver_thread_start(ctx->udprx);
	if (ret < 0) {
		fprintf(stderr, "Problem allocating the UDP receiver thread, aborting.\n");
		ret = -1;
		goto no_thread;
	}

	signal(SIGINT, signal_handler);
	gRunning = 1;

	if (ctx->monitor) {
		initscr();
		pthread_create(&ctx->threadId, 0, thread_func, ctx);
	}

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

	if (ctx->monitor) {
		ctx->threadTerminate = 1;
		while (!ctx->threadTerminated)
			usleep(50 * 1000);

		endwin();
	}

	ret = 0;

	printf("\nWrote %" PRIu64 " bytes to %s\n", ctx->bytesWritten, oname);

	printf("   PID    PacketCount   CCErrors\n");
	printf("---------------------- ---------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->stream.pids[i].enabled) {
			printf("0x%04x %14" PRIu64 " %10" PRIu64 "\n", i,
				ctx->stream.pids[i].packetCount,
				ctx->stream.pids[i].ccErrors);
		}
	}

no_thread:
	if (ctx->udprx)
		iso13818_udp_receiver_free(&ctx->udprx);

no_udp:
	if (ctx->url)
		url_free(ctx->url);

	fclose(ctx->ofh);

no_output:
	return ret;
}
