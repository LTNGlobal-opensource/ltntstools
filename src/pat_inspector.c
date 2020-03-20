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
static int gPATCount = 0;
static int gVerbose = 0;

static void DumpPAT(void* p_zero, dvbpsi_pat_t* p_pat)
{
	tstools_DumpPAT(p_zero, p_pat);
	dvbpsi_pat_delete(p_pat);
	gPATCount++;
}

static void usage(const char *progname)
{
	printf("A tool to display one or more PAT structures from a ISO13818 transport stream.\n");
	printf("Usage:\n");
	printf("  -i <inputfile.ts>\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int pat_inspector(int argc, char *argv[])
{
	int ch;
	dvbpsi_t *p_dvbpsi;
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

	if (gVerbose)
		p_dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_DEBUG);
	else
		p_dvbpsi = dvbpsi_new(&tstools_message, DVBPSI_MSG_NONE);
	if (p_dvbpsi == NULL)
		goto out;

	if (!dvbpsi_pat_attach(p_dvbpsi, DumpPAT, NULL))
		goto out;

	unsigned char buf[7 * 188];
	int ok = 1;
	while (ok)
	{
		int rlen = avio_read(puc, buf, sizeof(buf));
		if (rlen == -EAGAIN) {
			usleep(2 * 1000);
			continue;
		}

		for (int i = 0; i < rlen; i += 188) {
			uint16_t i_pid = ltntstools_pid(&buf[i]);
			if (i_pid == 0x0)
				dvbpsi_packet_push(p_dvbpsi, &buf[i]);

			if (gPATCount && !gDumpAll) {
				ok = 0;
				break;
			}
		}
	}
	avio_close(puc);

out:
	if (p_dvbpsi) {
		dvbpsi_pat_detach(p_dvbpsi);
		dvbpsi_delete(p_dvbpsi);
	}

	return 0;
}
