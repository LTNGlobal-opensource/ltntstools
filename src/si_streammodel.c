/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"

static int gVerbose = 0;
static int gDumpAll = 0;
static void *g_sm = NULL;

static void usage(const char *progname)
{
	printf("A tool to display the PAT/PMT transport tree structures from file.\n");
	printf("The first PAT and first set of PMTs are displayed, then the program terminates.\n");
	printf("Usage:\n");
	printf("  -i <inputfile.ts>\n");
	printf("  -a don't terminate after the first model is obtained\n");
	printf("  -v Increase level of verbosity (enable descriptor dumping).\n");
	printf("  -h Display command line help.\n");
}

int si_streammodel(int argc, char *argv[])
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
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	if (ltntstools_streammodel_alloc(&g_sm, NULL) < 0) {
		fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
		exit(1);
	}
	
	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	uint8_t buf[7 * 188];
	int ok = 1;
	while (ok) {
		int rlen = avio_read(puc, &buf[0], sizeof(buf));
		if (rlen == -EAGAIN) {
			usleep(2 * 1000);
			continue;
		}
		if (rlen < 0)
			break;

		int complete = 0;
		ltntstools_streammodel_write(g_sm, &buf[0], rlen / 188, &complete);

		if (complete) {
			if (gDumpAll == 0)
				break;

			struct ltntstools_pat_s *pat = NULL;
			if (ltntstools_streammodel_query_model(g_sm, &pat) == 0) {
//				ltntstools_pat_dprintf(pat, 0);
				ltntstools_pat_free(pat);
			}
		}

	}
	printf("Closing stream\n");
	avio_close(puc);

	struct ltntstools_pat_s *pat = NULL;
	if (ltntstools_streammodel_query_model(g_sm, &pat) == 0) {
		ltntstools_pat_dprintf(pat, 0);
		ltntstools_pat_free(pat);
	}

//	ltntstools_streammodel_dprintf(g_sm, 0);

	ltntstools_streammodel_free(g_sm);

	return 0;
}


