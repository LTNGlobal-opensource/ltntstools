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

#include "dump.h"
#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"

#include "../../sdk-dektec/LinuxSDK/DTAPI/Include/DTAPI.h"

#define DEFAULT_PORT 1

DtDevice      gdev;
DtInpChannel  ginput;

static int gRunning = 0;

struct tool_ctx_s
{
	int verbose;

	char *oname;

	int iport;

	int polarity;
	time_t lastOverFlowReport;

	struct ltntstools_throughput_s throughput;

	/* Output */
	AVIOContext *o_puc;
};

static void signal_handler(int signum)
{
	gRunning = 0;
}

static int configureDektec(struct tool_ctx_s *ctx)
{
	DTAPI_RESULT dr = gdev.AttachToType(2172, 0);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to attached to ASI device, aborting.\n");
		return -1;
	}

	dr = ginput.AttachToPort(&gdev, ctx->iport);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to attached to port, aborting.\n");
		return -1;
	}

	ginput.Reset(DTAPI_FULL_RESET);

	dr = ginput.SetRxControl(DTAPI_RXCTRL_IDLE);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to set idle, aborting.\n");
		return -1;
	}

    dr = ginput.ClearFifo();
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to clear fifo, aborting.\n");
		return -1;
	}

    dr = ginput.ClearFlags(0xFFFFFFFF);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to clear flags, aborting.\n");
		return -1;
	}

	int maxfifo;
	ginput.GetMaxFifoSize(maxfifo);
	printf("MaxFifoSize: %d\n", maxfifo);

#if 0
	/* The 2172 FIFO isn't cnfigurable. */
	dr = ginput.SetFifoSize(1 * 1048576);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to set fifosize, ignoring.\n");
	}
	ginput.GetMaxFifoSize(maxfifo);
	printf("MaxFifoSize: %d (new)\n", maxfifo);
#endif

	printf("\n");
	printf("Expected Latency @   5.00 mbps: %6.02f ms\n", (maxfifo * 8) / (5 * 1e6));
	printf("Expected Latency @  20.00 mbps: %6.02f ms\n", (maxfifo * 8) / (20 * 1e6));
	printf("Expected Latency @ 210.00 mbps: %6.02f ms\n", (maxfifo * 8) / (210 * 1e6));
	printf("\n");

	dr = ginput.SetIoConfig(DTAPI_IOCONFIG_IOSTD, DTAPI_IOCONFIG_ASI, -1);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to enable ASI rx mode, aborting.\n");
		return -1;
	}

	dr = ginput.PolarityControl(ctx->polarity);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to set polarity, aborting.\n");
		return -1;
	}

	int PacketSize;
	int NumInv;
	int ClkDet;
	int AsiLock;
	int RateOk;
	int AsiInv;		
	dr = ginput.GetStatus(PacketSize, NumInv, ClkDet, AsiLock, RateOk, AsiInv);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to query status, aborting.\n");
		return -1;
	}

	printf("ASI Signal: %s\n", AsiLock ? "Locked" : "Missing");
	printf("ASI    Inv: %d\n", AsiInv);

	dr = ginput.SetRxControl(DTAPI_RXCTRL_RCV);
	if (dr != DTAPI_OK) {
		fprintf(stderr, "Unable to set rx mode, aborting.\n");
		return -1;
	}

	return 0;
}

static void checkDektecOverflow(struct tool_ctx_s *ctx)
{
	// Check for overflow (only report overflow once)
	int Flags = 0, Latched = 0;
	DTAPI_RESULT dr = ginput.GetFlags(Flags, Latched);
	if (Latched & DTAPI_RX_FIFO_OVF)
	{
		time_t now = time(NULL);
		if (now != ctx->lastOverFlowReport) {
			ctx->lastOverFlowReport = now;
			char ts[64];
			libltntstools_getTimestamp(&ts[0], sizeof(ts), NULL);

			fprintf(stderr, "%s: ASI hardware overflow\n", ts);
		}
	}
	dr = ginput.ClearFlags(Latched);
}

static void usage(const char *progname)
{
	printf("Receive MPEG-TS from a DekTec ASI card and output to IP\n");
	printf("Usage:\n");
	printf("  -h Display command line help.\n");
	printf("  -i dektec asi port#                    [def: %d]\n", DEFAULT_PORT);
	printf("  -o <url>   Eg: udp://227.1.20.91:4091\n");
	printf("  -P 0|2|3   AUTO | Normal | Inverted    [def: 0]\n");
	printf("  -v Increase level of verbosity.\n");
	printf("\n  Example:\n");
	printf("    tstools_asi2ip -i 1 -o udp://227.1.20.91:4100\n");
	printf("\n");
}

static int _asi2ip(int argc, char *argv[])
{
	char ts[64];
	int ch;

	struct tool_ctx_s sctx, *ctx = &sctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->iport = DEFAULT_PORT;
	ctx->polarity = DTAPI_POLARITY_AUTO;

	while ((ch = getopt(argc, argv, "?hvi:o:P:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			ctx->iport = atoi(optarg);
			break;
		case 'o':
			ctx->oname = optarg;
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'P':
			ctx->polarity = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->oname == NULL) {
		fprintf(stderr, "\n-o is mandatory.\n\n");
		exit(1);
	}

	printf("\n");

	avformat_network_init();
	
	/* Configure the output */
	int ret = avio_open2(&ctx->o_puc, ctx->oname, AVIO_FLAG_WRITE | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-o syntax error\n");
		exit(1);
	}

	ret = configureDektec(ctx);
	if (ret < 0) {
		fprintf(stderr, "Unable to initialize dektex hardware, aborting.\n");
		exit(1);
	}

	printf("\n");

	signal(SIGINT, signal_handler);
	gRunning = 1;

	ltntstools_throughput_reset(&ctx->throughput);

	libltntstools_getTimestamp(&ts[0], sizeof(ts), NULL);
	printf("%s: Process starting\n", ts);

	char buf[7 * 188];
	int blen = sizeof(buf);

	time_t lastReport = 0;
	DTAPI_RESULT dr;
	int FifoLoad;
	int rem;
	while (gRunning) {
		dr = ginput.GetFifoLoad(FifoLoad);
		if (FifoLoad < blen) {
			usleep(1 * 1000);
			continue;
		}

		rem = FifoLoad;
		while (rem > blen) {
			dr = ginput.Read(buf, blen);
			rem -= (7 * 188);
			ltntstools_throughput_write(&ctx->throughput, (const uint8_t *)&buf[0], blen);
			avio_write(ctx->o_puc, (const unsigned char *)&buf[0], blen);
		}

		checkDektecOverflow(ctx);

		time_t now = time(NULL);
		if (now != lastReport) {
			lastReport = now;

			/* The dektec fifo on the STA2172 is fixed at 8MB. Calculate the
			 * bitrate of the stream and hence the overall latency.
			 */
			double mbps = ltntstools_throughput_get_mbps(&ctx->throughput);
			double ms = ((8 * 1048576) * 8) / (mbps * 1e6);
			libltntstools_getTimestamp(&ts[0], sizeof(ts), NULL);
            fprintf(stdout, "%s: %6.02f Mb/ps @ %6.02f ms\n", ts, mbps, ms);
		}

	}
	printf("user terminated....\n");

	ginput.SetRxControl(DTAPI_RXCTRL_IDLE);
	ginput.Detach(DTAPI_INSTANT_DETACH);
	gdev.Detach();

	avio_close(ctx->o_puc);

	return 0;
}

extern "C"
{
int asi2ip(int argc, char *argv[]) { return _asi2ip(argc, argv); }
};
