/* Send 7*TS UDP packets every N interval, to test
 * other tools that claim to correctly measure IAT intervals.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <libltntstools/ltntstools.h>

#define SLEEP_DEFAULT_US 1000

struct tool_ctx_s
{
	struct ltn_histogram_s *h;
	const char *ipaddr;
	int ipport;
	int sleep_us;
	int verbose;
	struct sockaddr_in sa;

	/* */
	int skt;
};

static void _usage(const char *prog)
{
	printf("Usage: %s\n", prog);
	printf("  -i sleep interval in us [def: %d]\n", SLEEP_DEFAULT_US);
	printf("  -a <ip address Eg. 234.1.1.1:1234>\n");
	printf("  -p <ip port Eg. 4001>\n");
	printf("  -v increase verbosity level\n");
}

int iat_tester(int argc, char* argv[])
{
	struct tool_ctx_s s_ctx, *ctx = &s_ctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->sleep_us = SLEEP_DEFAULT_US;

	int ch;

	while ((ch = getopt(argc, argv, "?hi:o:a:p:v")) != -1) {
		switch(ch) {
		case 'a':
			ctx->ipaddr = optarg;
			break;
		case 'i':
			ctx->sleep_us = atoi(optarg);
			break;
		case 'p':
			ctx->ipport = atoi(optarg);
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'h':
		case '?':
		default:
			_usage(argv[0]);
			exit(1);
		}
	}

	if (!ctx->ipaddr) {
		_usage(argv[0]);
		fprintf(stderr, "\n *** -a is mandatory ***\n");
		exit(1);
	}

	if (!ctx->ipport) {
		_usage(argv[0]);
		fprintf(stderr, "\n *** -p is mandatory ***\n");
		exit(1);
	}

	ltn_histogram_alloc_video_defaults(&ctx->h, "UDP transmit intervals");

	/* Create the UDP discover socket */
	ctx->skt = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->skt < 0) {
		fprintf(stderr, "Error allocating socket\n");
		return -1;
	}

	/* Non-blocking required */
	int fl = fcntl(ctx->skt, F_GETFL, 0);
	if (fcntl(ctx->skt, F_SETFL, fl | O_NONBLOCK) < 0) {
		fprintf(stderr, "Error setting non-blocking socket\n");
		return -1;
	}

	ctx->sa.sin_family = AF_INET;
	ctx->sa.sin_port = htons(ctx->ipport);
	ctx->sa.sin_addr.s_addr = inet_addr(ctx->ipaddr);

	unsigned char buf[7 * 188];
	memset(buf, 0xff, sizeof(buf));
	for (int i = 0; i < 7; i++) {
		ltntstools_generateNullPacket(&buf[i * 188]);
	}

	while (1) {
		sendto(ctx->skt, buf, sizeof(buf), 0, (struct sockaddr *)&ctx->sa, sizeof(ctx->sa));
		usleep(ctx->sleep_us);
	}

	printf("\n");
	ltn_histogram_interval_print(STDOUT_FILENO, ctx->h, 0);
	printf("\n");

	close(ctx->skt);
	ltn_histogram_free(ctx->h);

	return 0;
}
