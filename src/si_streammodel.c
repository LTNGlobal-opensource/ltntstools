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
#include "source-avio.h"

static int g_running = 1;
static int gVerbose = 0;
static int gDumpAll = 0;
static void *g_sm = NULL;

static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	int complete = 0;

    struct timeval nowtv;
    gettimeofday(&nowtv, NULL);
	ltntstools_streammodel_write(g_sm, pkts, packetCount, &complete, &nowtv);

	if (complete) {
		if (gDumpAll == 0) {
			g_running = 0;
			return NULL;
		}

		struct ltntstools_pat_s *pat = NULL;
		if (ltntstools_streammodel_query_model(g_sm, &pat) == 0) {
			ltntstools_pat_dprintf(pat, STDOUT_FILENO);
			ltntstools_pat_free(pat);
		}
	}

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to display the PAT/PMT transport tree structures from file.\n");
	printf("The first PAT and first set of PMTs are displayed, then the program terminates.\n");
	printf("Usage:\n");
	printf("  -i <filename | url> Eg: rtp|udp://234.1.1.1:4160?localaddr=172.16.0.67\n");
	printf("                          172.16.0.67 is the IP addr where we'll issue a IGMP join\n");
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
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

#if 0
	/* Fast and efficient */
	struct ltntstools_pat_s *pat;
	if (ltntstools_streammodel_alloc_from_url(iname, &pat) < 0) {
		fprintf(stderr, "Error parsing stream, no model found.\n");
	}

	ltntstools_pat_dprintf(pat, STDOUT_FILENO);
	ltntstools_pat_free(pat);
	return 0;
#else

	/* With more granular control. */
	if (ltntstools_streammodel_alloc(&g_sm, NULL) < 0) {
		fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
		exit(1);
	}

	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;

	void *srcctx = NULL;
	int ret = ltntstools_source_avio_alloc(&srcctx, NULL, &cbs, iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	while (g_running) {
		usleep(50 * 1000);
	}
	printf("Closing stream\n");
	ltntstools_source_avio_free(srcctx);

	struct ltntstools_pat_s *pat = NULL;
	if (ltntstools_streammodel_query_model(g_sm, &pat) == 0) {
		ltntstools_pat_dprintf(pat, STDOUT_FILENO);
		ltntstools_pat_free(pat);
	}

//	ltntstools_streammodel_dprintf(g_sm, STDOUT_FILENO);

	ltntstools_streammodel_free(g_sm);
#endif

	return 0;
}


