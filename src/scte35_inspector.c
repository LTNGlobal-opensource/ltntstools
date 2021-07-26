/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

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
#include <libklscte35/scte35.h>
#include "ffmpeg-includes.h"

static int gVerbose = 1;
static int gPID = 0;
static void *g_se = NULL;

static void usage(const char *progname)
{
	printf("A tool to display the SCTE35 packets from a file.\n");
	printf("Usage:\n");
	printf("    -i <url> Eg: udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
               "             192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -P 0xnnnn PID containing the SCTE35 messages.\n");
}

int scte35_inspector(int argc, char *argv[])
{
	int ch;
	char *iname = NULL;

	while ((ch = getopt(argc, argv, "?hvi:P:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'i':
			iname = optarg;
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &gPID) != 1) || (gPID > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'v':
			gVerbose = 1;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (gPID == 0) {
		fprintf(stderr, "\n-P is mandatory.\n\n");
		exit(1);
	}

	if (iname == NULL) {
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	if (ltntstools_sectionextractor_alloc(&g_se, gPID, 0xFC /* SCTE35 Table ID */) < 0) {
		fprintf(stderr, "\nUnable to allocate sectionextractor object.\n\n");
		exit(1);
	}
	
	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	int msgs = 0;
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
		ltntstools_sectionextractor_write(g_se, &buf[0], rlen / 188, &complete);

		if (complete) {
			unsigned char dst[256];
			int len = ltntstools_sectionextractor_query(g_se, &dst[0], sizeof(dst));
			if (len > 0) {
				printf("<-- Trigger %d --------------------------------------------------->\n", ++msgs);
				time_t now = time(0);
				printf("SCTE35 message on pid 0x%04x @ %s", gPID, ctime(&now));
				if (gVerbose > 0) {
					for (int i = 1; i <= len; i++) {
						if (i == 1 || i % 16 == 1)
							printf("\n  -> ");
						printf("%02x ", dst[i - 1]);
					}
					printf("\n");
					if (len % 16)
						printf("\n");
				}

				struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(dst, len);
				if (s) {
					/* Dump struct to console */
					scte35_splice_info_section_print(s);
					scte35_splice_info_section_free(s);
					printf("\n");
				}
			}
		}

	}
	avio_close(puc);

	ltntstools_sectionextractor_free(g_se);

	return 0;
}


