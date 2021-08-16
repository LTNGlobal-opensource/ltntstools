/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include "version.h"

/* External tool hooks */
extern int pat_inspector(int argc, char *argv[]);
extern int pmt_inspector(int argc, char *argv[]);
extern int si_inspector(int argc, char *argv[]);
extern int udp_capture(int argc, char *argv[]);
extern int pcap2ts(int argc, char *argv[]);
extern int clock_inspector(int argc, char *argv[]);
extern int pid_drop(int argc, char *argv[]);
extern int nic_monitor(int argc, char *argv[]);
extern int rtmp_analyzer(int argc, char *argv[]);
extern int tr101290_analyzer(int argc, char *argv[]);
extern int si_streammodel(int argc, char *argv[]);
extern int iat_tester(int argc, char *argv[]);
extern int ffmpeg_metadata(int argc, char *argv[]);
extern int scte35_inspector(int argc, char *argv[]);
extern int igmp_join(int argc, char *argv[]);
extern int slicer(int argc, char *argv[]);

typedef int (*func_ptr)(int, char *argv[]);

int main(int argc, char *argv[])
{
	printf("%s\n", COPYRIGHT);
	printf("Version: %s\n", GIT_VERSION);
	struct app_s {
		char *name;
		func_ptr func;
	} apps[] = {
#if 0
		{ "tstools_util",		demo_main, },
#endif
		{ "tstools_pat_inspector",	pat_inspector, },
		{ "tstools_pmt_inspector",	pmt_inspector, },
		{ "tstools_udp_capture",	udp_capture, },
		{ "tstools_si_inspector",	si_inspector, },
		{ "tstools_pcap2ts",		pcap2ts, },
		{ "tstools_clock_inspector",	clock_inspector, },
		{ "tstools_pid_drop",		pid_drop, },
		{ "tstools_nic_monitor",	nic_monitor, },
		{ "tstools_rtmp_analyzer",	rtmp_analyzer, },
		{ "tstools_tr101290_analyzer",	tr101290_analyzer, },
		{ "tstools_si_streammodel",	si_streammodel, },
		{ "tstools_iat_tester",		iat_tester, },
		{ "tstools_ffmpeg_metadata",	ffmpeg_metadata, },
		{ "tstools_scte35_inspector",	scte35_inspector, },
		{ "tstools_igmp_join",		igmp_join, },
		{ "tstools_slicer",		slicer, },
		{ 0, 0 },
	};
	char *appname = basename(argv[0]);

	int createLinks = 0;
	int listapps = 0;
	if ((argc == 2) && strcmp(argv[1], "--symlinks") == 0) {
		createLinks = 1;
	} else
	if ((argc == 2) && strcmp(argv[1], "--listapps") == 0) {
		listapps = 1;
	}

	int i = 0;
	struct app_s *app = &apps[i++];
	while (app->name) {
		if (listapps) {
			printf("%s\n", app->name);
		} else
		if (createLinks) {
			printf("creating link %s\n", app->name);
			symlink(argv[0], app->name);
		} else {
			if (strcmp(appname, app->name) == 0)
				return app->func(argc, argv);
		}

		app = &apps[i++];
	}
	if (createLinks || listapps)
		return 0;

	printf("No application called %s, aborting.\n", appname);
	i = 0;
	app = &apps[i++];
	while (app->name) {
		printf("%s ", app->name);
		app = &apps[i++];
	}

	return 1;
}
