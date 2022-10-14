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
#include "source-avio.h"

static int gDumpAll = 0;
static int gPATCount = 0;
static int gVerbose = 0;
static int gRunning = 1;
static dvbpsi_t *gp_dvbpsi = NULL;

static void DumpPAT(void* p_zero, dvbpsi_pat_t* p_pat)
{
	tstools_DumpPAT(p_zero, p_pat);
	dvbpsi_pat_delete(p_pat);
	gPATCount++;
}

static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	for (int i = 0; i < packetCount; i++) {
		uint16_t i_pid = ltntstools_pid(pkts + (i * 188));
		if (i_pid == 0x0) {
			if (gVerbose > 0) {
				printf("Pushing packet\n");
			}
			dvbpsi_packet_push(gp_dvbpsi, (uint8_t *)pkts + (i * 188));
		}

		if (gPATCount && !gDumpAll) {
			printf("Aborting\n");
			gRunning = 0;
			break;
		}
	}

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to display one or more PAT structures from a ISO13818 transport stream.\n");
	printf("Check one PAT, or EVERY pat, useful for version-change stream debugging.\n");
	printf("Usage:\n");
	printf("  -i <filename | url> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
           "                      192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -a process all pats, not just the first\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int pat_inspector(int argc, char *argv[])
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
		fprintf(stderr, "\n-i is mandatory.\n");
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

	if (gVerbose) {
		gp_dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_DEBUG);
	} else {
		gp_dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_NONE);
	}

	if (gp_dvbpsi == NULL) {
		goto out;
	}

	if (!dvbpsi_pat_attach(gp_dvbpsi, DumpPAT, NULL)) {
		goto out;
	}

	while (gRunning) {
		usleep(50 * 1000);
	}
	ltntstools_source_avio_free(srcctx);

out:
	if (gp_dvbpsi) {
		dvbpsi_pat_detach(gp_dvbpsi);
		dvbpsi_delete(gp_dvbpsi);
	}

	return 0;
}
