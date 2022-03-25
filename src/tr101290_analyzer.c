/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include "dump.h"
#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"

static int gDumpAll = 0;
static int gVerbose = 0;
static void *trhdl = NULL;

void *cb_notify(void *userContext, struct ltntstools_tr101290_alarm_s *array, int count)
{
	printf("%s(%p, %d)\n", __func__, array, count);
	for (int i = 0; i < count; i++) {
		struct ltntstools_tr101290_alarm_s *ae = &array[i];
		ltntstools_tr101290_event_dprintf(0, ae);
	}

	free((struct ltntstools_tr101290_alarm_s *)array);

	/* For fun, collect the entire summary in txt format. */
	ltntstools_tr101290_summary_report_dprintf(trhdl, 0);

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to collect transport packets from UDP and feed them into the TR101290 analyzer, reporting stream issues.\n");
	printf("Usage:\n");
	printf("  -i <inputfile.ts  udp://227.1.1.1:4001 etc>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int tr101290_analyzer(int argc, char *argv[])
{
	int ch;
	char *iname = NULL;

	while ((ch = getopt(argc, argv, "a?hvi:")) != -1) {
		switch (ch) {
		case 'a':
			gDumpAll = 1;
			break;
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			iname = optarg;
			break;
		case 'v':
			gVerbose = 1;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (iname == NULL) {
		fprintf(stderr, "-i is mandatory.\n");
		exit(1);
	}

	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	ltntstools_tr101290_alloc(&trhdl, (ltntstools_tr101290_notification)cb_notify, NULL);

	unsigned char buf[7 * 188];
	int ok = 1;
	while (ok)
	{
		int rlen = avio_read(puc, buf, sizeof(buf));
		if (rlen == -EAGAIN) {
			usleep(2 * 1000);
			continue;
		}

		ssize_t s = ltntstools_tr101290_write(trhdl, buf, rlen / 188);
		if (s) { }
	}
	avio_close(puc);

	ltntstools_tr101290_free(trhdl);

	return 0;
}
