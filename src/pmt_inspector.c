/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>

#include <libltntstools/ltntstools.h>
#include "dump.h"
#include "source-avio.h"

#define DEFAULT_PID 0x30

static int gRunning = 1;
static int gDumpAll = 0;
static int gPMTCount = 0;
static int gVerbose = 0;
static uint32_t gi_program_number = 1, gi_pmt_pid = DEFAULT_PID;
static dvbpsi_t *gp_dvbpsi = NULL;

static void DumpPMT(void *p_zero, dvbpsi_pmt_t * p_pmt)
{
	tstools_DumpPMT(p_zero, p_pmt, gVerbose > 0, gi_pmt_pid);
	dvbpsi_pmt_delete(p_pmt);
	gPMTCount++;
}

static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	for (int i = 0; i < packetCount; i++) {
		if (ltntstools_pid(pkts + (i * 188)) == gi_pmt_pid) {
			if (gVerbose > 1) {
				ltntstools_hexdump((unsigned char *)pkts + (i * 188), 188, 32 + 1);
			}
			dvbpsi_packet_push(gp_dvbpsi, (uint8_t *)pkts + (i * 188));
		}
	}

	if (gPMTCount && !gDumpAll) {
		gRunning  = 0;
	}

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to display one or more PMT structures from a ISO13818 transport stream.\n");
	printf("Check one PMT, or EVERY PMT, useful for version-change stream debugging.\n");
	printf("Usage:\n");
	printf("  -i <filename | url> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
           "                      192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -a process all pmts, not just the first\n");
	printf("  -n program/service number [def: %d]\n", gi_program_number);
	printf("  -P 0xnnnn PID containing the program elementary stream [def: 0x%02x]\n", DEFAULT_PID);
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int pmt_inspector(int argc, char *argv[])
{
	int ch;
	char *iname = NULL;

	while ((ch = getopt(argc, argv, "a?hvi:P:n:")) != -1) {
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
			iname = strdup(optarg);
			break;
		case 'n':
			gi_program_number = atoi(optarg);
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &gi_pmt_pid) != 1) || (gi_pmt_pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'v':
			gVerbose++;
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

	gp_dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_NONE);
	if (gp_dvbpsi == NULL) {
		goto out;
	}

	if (!dvbpsi_pmt_attach(gp_dvbpsi, gi_program_number, DumpPMT, NULL)) {
		goto out;
	}


	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;

	void *srcctx = NULL;
	int ret = ltntstools_source_avio_alloc(&srcctx, NULL, &cbs, iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	while (gRunning) {
		usleep(50 * 1000);
	}

	ltntstools_source_avio_free(srcctx);

out:
	if (gp_dvbpsi) {
		dvbpsi_pmt_detach(gp_dvbpsi);
		dvbpsi_delete(gp_dvbpsi);
	}
	free(iname);

	return 0;
}
