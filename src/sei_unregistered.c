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
#include "ffmpeg-includes.h"

static int gVerbose = 0;

static void findSEIUnregistered(unsigned char *buf, int lengthBytes, uint32_t offset)
{
	unsigned char pattern[] = { 0x00, 0x00, 0x01, 0x06, 0x05 };

	for (int i = 0; i < lengthBytes - 5; i++) {
		if (memcmp(buf + i, &pattern[0], sizeof(pattern)) == 0) {
			printf("offset 0x%08x : ", offset + i);

			int truncated = 0;
			int len = 32;
			if (gVerbose) {
				len = 5 + *(buf + i + 5);
			}
			if (len > (lengthBytes - i)) {
				len = lengthBytes - i;
				truncated = 1;
			}

			for (int j = 0; j < len; j++)
				printf("%02x ", *(buf + i + j));
			if (truncated)
				printf(" ... <snip>");
			printf("\n");
		}
	}
}
static void usage(const char *progname)
{
	printf("A tool to find SEI UNREGISTERED data patterns in video files.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
		"           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int sei_unregistered(int argc, char *argv[])
{
	int ch;
	char *iname = NULL;

	while ((ch = getopt(argc, argv, "?hvi:")) != -1) {
		switch (ch) {
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

	avformat_network_init();
	AVIOContext *puc;
	int ret = avio_open2(&puc, iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	uint32_t offset = 0;
	int blen = 128 * 188;
	uint8_t *buf = malloc(blen);
	int ok = 1;
	while (ok) {
		int rlen = avio_read(puc, buf, blen);
		if (rlen == -EAGAIN) {
			usleep(2 * 1000);
			continue;
		}
		if (rlen < 0)
			break;

		findSEIUnregistered(buf, rlen, offset);

		offset += rlen;
	}
	printf("Closing stream\n");
	avio_close(puc);
	free(buf);

	return 0;
}
