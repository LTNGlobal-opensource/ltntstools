/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <libltntstools/ltntstools.h>
#include "parsers.h"
#include "utils.h"

static int gRunning = 0;

struct tool_context_s
{
	char *iname;
	char *ifname;
	int verbose;
	int stopAfterSeconds;

#define MAX_ADDRESS_COUNT 64
	int addressCount;
	struct parser_ippid_s address[MAX_ADDRESS_COUNT];
	void *joinHandles[MAX_ADDRESS_COUNT];

#ifdef __linux__
	timer_t timerId;
#endif
};

static void signal_handler(int signum)
{
	gRunning = 0;
}

#ifdef __linux__
static void timer_thread(union sigval arg)
{
	printf("Terminating due to -t condition\n");
	signal_handler(0);
}

static void terminate_after_seconds(struct tool_context_s *ctx, int seconds)
{
	struct sigevent se;
	se.sigev_notify = SIGEV_THREAD;
	se.sigev_value.sival_ptr = &ctx->timerId;
	se.sigev_notify_function = timer_thread;
	se.sigev_notify_attributes = NULL;

	struct itimerspec ts;
	ts.it_value.tv_sec = seconds;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;

	int ret = timer_create(CLOCK_REALTIME, &se, &ctx->timerId);
	if (ret < 0) {
		fprintf(stderr, "Failed to create termination timer.\n");
		return;
	}

	ret = timer_settime(ctx->timerId, 0, &ts, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to start termination timer.\n");
		return;
	}
}
#endif

static void usage(const char *progname)
{
	printf("A tool to issue IGMP joins on a specific multicast group and interface.\n");
	printf("Up to %d joins are supported on a single interface, via multiple -a options.\n", MAX_ADDRESS_COUNT);
	printf("Each process supports only one NIC, don't issue multiple -i args.\n");
	printf("Usage:\n");
	printf("  -i <nicname> Eg: eno2\n");
	printf("  -a <url> Eg: udp://234.1.1.1:4160\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
#ifdef __linux__
	printf("  -t <#seconds>. Stop after N seconds [def: 0 - unlimited]\n");
#endif
	printf("\nExample:\n");
	printf("  ./tstools_igmp_join -i net1 -a udp://227.1.1.1:4001 -a udp://227.1.1.2:4002     -- Issue two joins on net1\n");
}

int igmp_join(int argc, char *argv[])
{
	int ret = 0;
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));

	while ((ch = getopt(argc, argv, "?ha:i:vt:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'a':
			ctx->iname = optarg;
			ret = parsers_ippid_parse(ctx->iname, &ctx->address[ctx->addressCount]);
			if (ret < 0) {
				fprintf(stderr, "Error parsing address, err = %d\n", ret);
				exit(1);
			}
			ctx->addressCount++;
			if (ctx->addressCount >= MAX_ADDRESS_COUNT) {
				fprintf(stderr, "Too many joins, limit is %d, aborting\n", MAX_ADDRESS_COUNT);
				exit(1);
			}
			break;
		case 'i':
			ctx->ifname = optarg;
			if (!networkInterfaceExists(ctx->ifname)) {
				fprintf(stderr, "\nNo such network interface '%s', available interfaces:\n", ctx->ifname);
				networkInterfaceList();
				printf("\n");
				exit(1);
			}
			break;
		case 'v':
			ctx->verbose++;
			break;
#ifdef __linux__
		case 't':
			ctx->stopAfterSeconds = atoi(optarg);
			break;
#endif
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-a is mandatory.\n\n");
		exit(1);
	}
	if (ctx->ifname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

	if (ctx->stopAfterSeconds) {
#ifdef __linux__
		terminate_after_seconds(ctx, ctx->stopAfterSeconds);
#endif
	}

	for (int i = 0; i < ctx->addressCount; i++) {
		ret = ltntstools_igmp_join(&ctx->joinHandles[i], ctx->address[i].address, ctx->address[i].port, ctx->ifname);
		if (ret < 0) {
			fprintf(stderr, "Unable to join address %s:%d, aborting\n", ctx->address[i].address, ctx->address[i].port);
			exit(1);
		}
	}

	printf("<CTRL-C> to exit\n");
	
	signal(SIGINT, signal_handler);
	gRunning = 1;
	while (gRunning) {
		usleep(50 * 1000);
	}

	for (int i = 0; i < ctx->addressCount; i++) {
		if (ctx->joinHandles[i])
			ltntstools_igmp_drop(ctx->joinHandles[i]);
	}

	ret = 0;

	return ret;
}
