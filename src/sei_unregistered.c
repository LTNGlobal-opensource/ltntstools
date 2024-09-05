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
#include "source-avio.h"

static int gVerbose = 0;
static uint32_t goffset = 0;
static int doT35 = 0;
static int doFiller = 0;
static void *nalfinder = NULL;

static void findSEIFillerPayload(unsigned char *buf, int lengthBytes, uint32_t offset)
{
	unsigned char pattern[] = { 0x00, 0x00, 0x01, 0x06, 0x03 };

	for (int i = 0; i < lengthBytes - 5; i++) {
		if (memcmp(buf + i, &pattern[0], sizeof(pattern)) == 0) {
			printf("fill  offset 0x%08x : ", offset + i);

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

static void findSEIT35(unsigned char *buf, int lengthBytes, uint32_t offset)
{
	unsigned char pattern[] = { 0x00, 0x00, 0x01, 0x06, 0x04 };
	unsigned char hevc_pattern[] = { 0x00, 0x00, 0x01, };
	int h264_found = 0;

	for (int i = 0; i < lengthBytes - 5; i++) {
		if (memcmp(buf + i, &pattern[0], sizeof(pattern)) == 0) {
			printf("  AVC t.35 offset 0x%08x : ", offset + i);

			int truncated = 0;
			int len = 42;
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

	if (h264_found == 1)
		return;

	/* Look for HEVC SEI captions */
	for (int i = 0; i < lengthBytes - 10; i++) {
		if (memcmp(buf + i, &hevc_pattern[0], sizeof(hevc_pattern)) == 0) {
			if (((*(buf + i + 3) & 0x7e) >> 1 == 39 /* PREFIX SEI TYPE*/) || ((*(buf + i + 3) & 0x7e) >> 1 == 40 /* SIFFUX SEI TYPE*/)){
				if (*(buf + i + 5) == 0x04 /*registered t35 */) {
					printf(" HEVC t.35 offset 0x%08x : ", offset + i);
					int truncated = 0;
					int len = *(buf + i + 6) + 1 + 7;
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
	}

}

static void findSEIUnregistered(unsigned char *buf, int lengthBytes, uint32_t offset)
{
	unsigned char pattern[] = { 0x00, 0x00, 0x01, 0x06, 0x05 };

	for (int i = 0; i < lengthBytes - 5; i++) {
		if (memcmp(buf + i, &pattern[0], sizeof(pattern)) == 0) {
			printf("unreg offset 0x%08x : ", offset + i);

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


static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	if (doT35) {
		findSEIT35((uint8_t *)pkts, packetCount * 188, goffset);
	}

	if (doFiller) {
		findSEIFillerPayload((uint8_t *)pkts, packetCount * 188, goffset);
	}
		
	findSEIUnregistered((uint8_t *)pkts, packetCount * 188, goffset);

	if (nalfinder) {
		h264_slice_counter_write(nalfinder, pkts, packetCount);
	}

	goffset += (packetCount * 188);

	return NULL;
}

static void usage(const char *progname)
{
	printf("A tool to find SEI UNREGISTERED data patterns, or T35 Captions, or filler/padding SEI segments in H.264 streams.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
		"           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -c Find caption SEIs in H.264 [Default: disabled].\n");
	printf("  -f Find filler payload SEIs in H.264 [Default: disabled].\n");
	printf("  -P 0xnnnn Search video PID for FILLER NAL types [def: disabled]\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
}

int sei_unregistered(int argc, char *argv[])
{
	int ch;
	char *iname = NULL;
	int pid;

	while ((ch = getopt(argc, argv, "?hcfvi:P:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'c':
			doT35 = 1;
			break;
		case 'f':
			doFiller = 1;
			break;
		case 'i':
			iname = optarg;
			break;
		case 'v':
			gVerbose = 1;
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &pid) != 1) || (pid > 0x1fff)) {
				usage(argv[0]);
				exit(1);
			}
			nalfinder = h264_slice_counter_alloc(pid);
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

	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;

	void *srcctx = NULL;
	int ret = ltntstools_source_avio_alloc(&srcctx, NULL, &cbs, iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	int ok = 1;
	while (ok) {
		usleep(50 * 1000);
	}
	printf("Closing stream\n");

	ltntstools_source_avio_free(srcctx);

	if (nalfinder) {
		h264_slice_counter_dprintf(nalfinder, STDOUT_FILENO, 1);
		h264_slice_counter_free(nalfinder);
	}

	return 0;
}
