#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>

#include <libltntstools/ltntstools.h>
#include <srt/srt.h>

#include "utils.h"

static int g_running = 0;

struct tool_ctx_s
{
	struct ltn_histogram_s *h;
	int verbose;
	char *filename;
	char *passPhrase;
	int fileLoops;

	/* transport file smoother */
	void *sm;
	double fileLoopPct;

	/* SRT */
	SRTSOCKET skt;
	struct sockaddr_in sa;
	char *streamId;
	char hostname[96];
	int port;
	struct hostent *he;
	SRT_TRACEBSTATS stats;
};

static void signal_handler(int signum)
{
	g_running = 0;
}

static void tool_srt_close(struct tool_ctx_s *ctx)
{
	if (ctx->skt != -1)
		srt_close(ctx->skt);
	ctx->skt = -1;
}

static int tool_srt_reopen(struct tool_ctx_s *ctx)
{
	tool_srt_close(ctx);

	ctx->skt = srt_create_socket();
	if (ctx->skt < 0) {
		fprintf(stderr, "%s() unable to create srt socket\n", __func__);
		return -1;
	}

	memset(&ctx->sa, 0, sizeof(ctx->sa));

	ctx->sa.sin_family = AF_INET;
	ctx->sa.sin_port = htons(ctx->port);
	memcpy(&ctx->sa.sin_addr, ctx->he->h_addr_list[0], ctx->he->h_length);

	if (ctx->streamId) {
		srt_setsockflag(ctx->skt, SRTO_STREAMID, ctx->streamId, strlen(ctx->streamId));
	}
	if (ctx->passPhrase) {
		srt_setsockflag(ctx->skt, SRTO_PASSPHRASE, ctx->passPhrase, strlen(ctx->passPhrase));
	}

	/* Don't linger and block when _clsoe is called, do an immediate terminate. */
	uint32_t v = 0;
	srt_setsockflag(ctx->skt, SO_LINGER, &v, sizeof(v));

	printf("\nConnecting to srt://%s:%d (%s) ... ", ctx->hostname, ctx->port,
		ctx->fileLoops ? "loop" : "single playout");

	int st = srt_connect(ctx->skt, (struct sockaddr *)&ctx->sa, sizeof(ctx->sa));
	if (st < 0) {
		printf("failed to connect to srt receiver\n");
	} else {
		printf("Connected.\n");
	}

	return st;
}

/* Called by the rate controlled file transfer player, to give us positional player information.
 */
static void *sm_cb_pos(void *userContext, uint64_t pos, uint64_t max, double pct)
{
	struct tool_ctx_s *ctx = userContext;
	ctx->fileLoopPct = pct;
	printf("Complete: %6.2f%%\r", pct);
	fflush(0);

	if (pct >= 100.0L && ctx->fileLoops == 0) {
		/* Shutdown the playout. */
		printf("\nEnd of content, stopping playouts\n");
		g_running = 0;
	} else
	if (pct >= 100.0L && ctx->fileLoops == 1 && g_running == 1) {
		/* Repeat the playout. */
		printf("\nEnd of content, repeat begins\n");
	}

	return NULL;
}

/* Called by the rate controlled file transfer player, to give us packets.
 */
static void * sm_cb_raw(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct tool_ctx_s *ctx = userContext;

	int nb = srt_sendmsg(ctx->skt, (const char *)pkts, packetCount * 188, -1, 1);
	if (nb < 0) {
		fprintf(stderr, "Failure to send message, re-opening the connection\n");
		tool_srt_reopen(ctx);
		return NULL;
	} else {
		ltn_histogram_interval_update(ctx->h);
	}

	if (ctx->verbose >= 2) {
		ltn_histogram_interval_print(STDOUT_FILENO, ctx->h, 1);
	}

	return NULL;
}

static void _usage(const char *prog)
{
	printf("A tool to playout PCR rate controlled ISO13818-1 SPTS/MPTS transport files to a remote SRT receiver.\n");
	printf("Usage: %s\n", prog);
	printf("  -i <filename> MPEG-TS filename\n");
	printf("  -l loop file endlessly. [def: no]\n");
	printf("  -v increase verbosity level, level 1 and 2 produce udp playout histograms\n");
	printf("  -o srt://host:port [mandatory]\n");
	printf("  -p SRT encryption passphrase (min 10 chars max 79) [optional]");
	printf("  -s <srt streamid> [optional]\n");
}

int srt_transmit(int argc, char* argv[])
{
	struct tool_ctx_s s_ctx, *ctx = &s_ctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->fileLoops = 0;

	int ch;

	while ((ch = getopt(argc, argv, "?hi:vlo:p:s:")) != -1) {
		switch(ch) {
		case 'i':
			if (ctx->filename)
				free(ctx->filename);
			ctx->filename = strdup(optarg);

			if (!isValidTransportFile(ctx->filename)) {
				fprintf(stderr, "\ninput filename is missing or problematic, aborting.\n");
				exit(1);
			}
			break;
		case 'l':
			ctx->fileLoops = 1;
			break;

		case 'o':
			if (sscanf(optarg, "srt://%99[^:]:%d", &ctx->hostname[0], &ctx->port) != 2) {
				fprintf(stderr, "Syntax error, requires srt://hostname:port, aborting.\n");
				exit(1);
			}

			ctx->he = gethostbyname(ctx->hostname);
			if (!ctx->he) {
				fprintf(stderr, "\nUnable to locate output hostname, DNS didn't resolve it, aborting.\n");
				return -1;
			}
			if (ctx->port <= 0 || ctx->port > 65535) {
				fprintf(stderr, "\nIllegal port number, aborting.\n");
				return -1;
			}

			break;
		case 'p':
			if (ctx->passPhrase)
				free(ctx->passPhrase);
			ctx->passPhrase = strdup(optarg);
			break;
		case 's':
			if (ctx->streamId)
				free(ctx->streamId);
			ctx->streamId = strdup(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'h':
		case '?':
		default:
			_usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->port == 0) {
		fprintf(stderr, "-o srt://host:port is mandatory, aborting\n");
		exit(1);
	}

	printf("\nStream Encryption : %s\n", ctx->passPhrase ? "on" : "off");
	printf("   Stream Path/ID : %s\n", ctx->streamId ? ctx->streamId : "<disabled>");

	ltn_histogram_alloc_video_defaults(&ctx->h, "SRT transmit intervals");

	/* See
	 * https://github.com/hwangsaeul/libsrt/blob/master/docs/API.md#setup-and-teardown
	 */
	srt_startup();

	/* Setup the srt outbound connection */
	tool_srt_reopen(ctx);

	/* Configure the rate controlled TS framework */
	struct ltntstools_source_rcts_callbacks_s sm_callbacks = { 0 };
	sm_callbacks.raw = (ltntstools_source_rcts_raw_callback)sm_cb_raw;
	sm_callbacks.pos = (ltntstools_source_rcts_pos_callback)sm_cb_pos;

	/* Initialize a rate Controlled Transport Stream input object. */
	if (ltntstools_source_rcts_alloc(&ctx->sm, ctx, &sm_callbacks, ctx->filename, ctx->fileLoops) < 0) {
		fprintf(stderr, "%s() Unable to open filename, aborting.\n", __func__);
		exit(1);
	}

	/* Sit in a loop, waiting for a ctrl-c signal, or for playout to naturally stop */
	signal(SIGINT, signal_handler);
	g_running = 1;
	int timeout = 2000;
	while (g_running) {
		usleep(50 * 1000);
		timeout -= 50;
		if (timeout < 0) {
			timeout = 5000;

			/* https://github.com/hwangsaeul/libsrt/blob/master/docs/statistics.md#mbpsSendRate */
			if (srt_bistats(ctx->skt, &ctx->stats, 0, 1) == 0) {
				printf("\nMb/ps: %7.02f\tBytes: %12" PRIu64 "\tRTT: %7.0f\tSendLoss: %8d\tSendDrop: %8d\tRetrans: %8d\n",
					ctx->stats.mbpsSendRate,
					ctx->stats.byteSentTotal,
					ctx->stats.msRTT,
					ctx->stats.pktSndLossTotal,
					ctx->stats.pktSndDropTotal,
					ctx->stats.pktRetransTotal);
			}
		}
	}
	printf("\n");

	/* Teardown */
	ltntstools_source_rcts_free(ctx->sm);
	tool_srt_close(ctx);
	srt_cleanup();

	if (ctx->verbose) {
		printf("\n");
		ltn_histogram_interval_print(STDOUT_FILENO, ctx->h, 0);
		printf("\n");
	}

	ltn_histogram_free(ctx->h);

	if (ctx->filename) {
		free(ctx->filename);
		ctx->filename = NULL;
	}
	if (ctx->streamId) {
		free(ctx->streamId);
		ctx->streamId = NULL;
	}
	if (ctx->passPhrase) {
		free(ctx->passPhrase);
		ctx->passPhrase = NULL;
	}

	return 0;
}
