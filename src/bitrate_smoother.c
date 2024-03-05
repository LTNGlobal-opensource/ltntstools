/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

/*
 tstools_bitrate_smoother -i udp://127.0.0.1:4001?buffer_size=250000 \
                          -o udp://127.0.0.1:4002?pkt_size=1316 -b 20000000 -P 0x500
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <curses.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>
#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "kbhit.h"

#define DEFAULT_LATENCY 100

char *strcasestr(const char *haystack, const char *needle);

/* We previously had ENABLE_PIR_CORRECTOR disabled code here,
 * that demonstrated patching PIR streams.
 * It was non-functional and removed, but if you want it, check out
 * hash 087d51a10d46d11e33a71c95d8f6934793f71b1f
 */

static int gRunning = 0;

struct tool_context_s
{
	char *iname, *oname;
	int verbose;
	int stopAfterSeconds;
	int terminateLOSSeconds;

	struct ltntstools_stream_statistics_s *i_stream, *o_stream;
	void *smoother;

	pthread_t threadId;
	int trailerRow;
	int threadTerminate, threadRunning, threadTerminated;

#ifdef __linux__
	timer_t timerId;
#endif

	/* ffmpeg related */
	pthread_t ffmpeg_threadId;
	int ffmpeg_threadTerminate, ffmpeg_threadRunning, ffmpeg_threadTerminated;
	AVIOContext *i_puc;
	AVIOContext *o_puc;

	int latencyMS;
	int pcrPID;    /* UDP-TS only */
	int isRTP;     /* Boolean. True = RTP mode, false = UDP-TS PCR mode */

	/* The reframer used only in UDP-TS mode, NOT in RTP mode, to create 7*188 packet lengths. */
	struct ltntstools_reframer_ctx_s *reframer;

	void *sm; /* StreamModel Context */
	int smcomplete;

	struct rtp_hdr_analyzer_s rtp_stream_in, rtp_stream_out;

	/* Pid filter */
	unsigned char filter[8192];
	unsigned int pid;

};

/* Reframer hands us 7*188 buffers, guaranteed. Send to the UDP. */
static void *reframer_cb(void *userContext, const uint8_t *buf, int lengthBytes)
{
	struct tool_context_s *ctx = userContext;
	avio_write(ctx->o_puc, buf, lengthBytes);
	return NULL;
}

static int smoother_pcr_cb(void *userContext, unsigned char *buf, int byteCount,
	struct ltntstools_pcr_position_s *array, int arrayLength)
{
	struct tool_context_s *ctx = userContext;
	
	if (ctx->verbose & 8) { /* Output hex dump */
		for (int i = 0; i < arrayLength; i++) {
			struct ltntstools_pcr_position_s *e = &array[i];
			char *ts = NULL;
			ltntstools_pcr_to_ascii(&ts, e->pcr);
			printf("%s : %14" PRIi64 ", %8" PRIu64 ", %04x\n",
				ts,
				e->pcr, e->offset, e->pid);
			free(ts);
		}
	}
	for (int i = 0; i < byteCount; i += 188) {
		uint16_t pidnr = ltntstools_pid(buf + i);
		struct ltntstools_pid_statistics_s *pid = &ctx->o_stream->pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = ltntstools_continuity_counter(buf + i);
		if (ltntstools_isCCInError(buf + i, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
				char ts[256];
				time_t now = time(0);
				sprintf(ts, "%s", ctime(&now));
				ts[ strlen(ts) - 1] = 0;
				printf("%s: %s() CC Error : pid %04x -- Got 0x%x wanted 0x%x\n", ts, __func__, pidnr, cc, (pid->lastCC + 1) & 0x0f);
				printf("scb %02x %02x %02x %02x %02x %02x %02x %02x\n",
					*(buf + i + 0),
					*(buf + i + 1),
					*(buf + i + 2),
					*(buf + i + 3),
					*(buf + i + 4),
					*(buf + i + 5),
					*(buf + i + 6),
					*(buf + i + 7)
				);
				pid->ccErrors++;
			}
		}

		pid->lastCC = cc;

		if (ltntstools_tei_set(buf + i))
			pid->teiErrors++;

		if (ctx->verbose & 2) {
			for (int i = 0; i < byteCount; i += 188) {
				for (int j = 0; j < 24; j++) {
					printf("%02x ", buf[i + j]);
					if (j == 3)
						printf("-- 0x%04x(%4d) -- ", pidnr, pidnr);
				}
				printf("\n");
			}
		}
	}

	ltststools_reframer_write(ctx->reframer, buf, byteCount);

	return 0;
}

static void print_rtp_buffer(struct tool_context_s *ctx, const unsigned char *buf, int byteCount)
{
	struct rtp_hdr *hdr = (struct rtp_hdr *)buf;
	int tspktcount = ((byteCount - 12) / 188);

	char *ts = NULL;
	ltntstools_pts_to_ascii(&ts, ntohl(hdr->ts));
	printf("@ %s : %14" PRIu32 " -- RTP: [ ", ts, ntohl(hdr->ts));
	free(ts);

	/* Hexdump of the RTP header */
	for (int j = 0; j < 12; j++) {
		printf("%02x ", buf[j]);
	}
	printf("] = %d bytes, seq %d\n", byteCount, ntohs(hdr->seq));

	/* Hexdump, beginning of each TS packet */
	for (int i = 0; i < tspktcount; i++) {
		printf("  -> ");
		for (int j = 0; j < 12; j++) {
			printf("%02x ", buf[12 + (i * 188) + j]);
		}
		printf("\n");
	}
}

static int smoother_rtp_cb(void *userContext, const unsigned char *buf, int byteCount)
{
	struct tool_context_s *ctx = userContext;

	/* No need to reframe, just output the RTP as it came from the smoother. */

	/* Monitor for RTP sequence problems. */
	rtp_hdr_write(&ctx->rtp_stream_out, (struct rtp_hdr *)buf);
	// TODO: Analyze stats for problems

	/* TODO: Monitor for CC sequence problems. */

	/* In verbose mode, show the output hex. */
	if (ctx->verbose & 2) { /* Output hex dump */
		print_rtp_buffer(ctx, buf, byteCount);
	}

	avio_write(ctx->o_puc, buf, byteCount);

	return 0;
}

static void *packet_cb(struct tool_context_s *ctx, unsigned char *buf, int byteCount)
{
	for (int i = 0; i < byteCount; i += 188) {
		uint16_t pidnr = ltntstools_pid(buf + i);
		struct ltntstools_pid_statistics_s *pid = &ctx->i_stream->pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = ltntstools_continuity_counter(buf + i);
		if (ltntstools_isCCInError(buf + i, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
				char ts[256];
				time_t now = time(0);
				sprintf(ts, "%s", ctime(&now));
				ts[ strlen(ts) - 1] = 0;
				printf("%s: %s() CC Error : pid %04x -- Got 0x%x wanted 0x%x\n", ts, __func__, pidnr, cc, (pid->lastCC + 1) & 0x0f);
				printf("pcb %02x %02x %02x %02x %02x %02x %02x %02x\n",
					*(buf + i + 0),
					*(buf + i + 1),
					*(buf + i + 2),
					*(buf + i + 3),
					*(buf + i + 4),
					*(buf + i + 5),
					*(buf + i + 6),
					*(buf + i + 7)
				);
				pid->ccErrors++;
			}
		}

		pid->lastCC = cc;

		if (ltntstools_tei_set(buf + i))
			pid->teiErrors++;

		if (ctx->verbose & 1) {
			for (int i = 0; i < byteCount; i += 188) {
				for (int j = 0; j < 24; j++) {
					printf("%02x ", buf[i + j]);
					if (j == 3)
						printf("-- 0x%04x(%4d) -- ", pidnr, pidnr);
				}
				printf("\n");
			}
		}
	}

	return 0;
}

static void *thread_packet_rx(void *p)
{
	struct tool_context_s *ctx = p;
	ctx->ffmpeg_threadRunning = 1;
	ctx->ffmpeg_threadTerminate = 0;
	ctx->ffmpeg_threadTerminated = 0;

	pthread_detach(ctx->ffmpeg_threadId);

	int buflen = 188 * 1024;
	unsigned char *buf = malloc(buflen);
	int boffset = 0;

	if (ctx->isRTP) {
		printf("RTP IS CURRENT DISABLED, DO NOT USE FOR RTP, aborting\n");
		exit(0);
//		buflen += 12;
//		boffset = 12;
	}

	time_t lastPacketTime = time(0);

	char ts[256];
	time_t now = time(0);
	sprintf(ts, "%s", ctime(&now));
	ts[ strlen(ts) - 1] = 0;
	printf("%s: Smoother starting\n", ts);

	while (!ctx->ffmpeg_threadTerminate) {
		if (ctx->terminateLOSSeconds && (lastPacketTime + ctx->terminateLOSSeconds <= now)) {
			char ts[256];
			time_t now = time(0);
			sprintf(ts, "%s", ctime(&now));
			ts[ strlen(ts) - 1] = 0;

			/* We lost input packets for N seconds. Terminate cleanly. */
			printf("%s: LOS occured for %d seconds. Terminating at %s",
				ts,
				ctx->terminateLOSSeconds,
				ctime(&now));
			exit(1);
		}

		int rlen = avio_read(ctx->i_puc, buf, buflen);
		if (ctx->verbose & 1) {
			printf("source received %d bytes (EAGAIN %d ETIMEDOUT %d)\n", rlen, -EAGAIN, -ETIMEDOUT);
		}
		now = time(0);
		if ((rlen == -EAGAIN) || (rlen == -ETIMEDOUT)) {
			usleep(1 * 1000);
			continue;
		} else
		if (rlen < 0) {
			usleep(1 * 1000);
			gRunning = 0;
			/* General Error or end of stream. */
			continue;
		}

		if (rlen < 1) {
			usleep(1 * 1000);
			continue;
		}

		/* Pid filter, convery any blocked pids into null packets */
		for (int i = 0; i < rlen; i += 188) {
			unsigned char *p = buf + i;
			uint16_t pidnr = ltntstools_pid(buf + i);

			/* If the pid is blocked from passing, convert it into a null packet
			 * before it enters the smoother
			 */
			if (ctx->filter[pidnr] == 0) {
				ltntstools_generateNullPacket(p);
			}
		}
		if (ctx->isRTP == 0 && ctx->sm == NULL && ctx->pcrPID == 0) {
			if (ltntstools_streammodel_alloc(&ctx->sm, NULL) < 0) {
				fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
				exit(1);
			}
		} else
		if (ctx->isRTP == 0 && ctx->sm == NULL && ctx->pcrPID && ctx->smoother == NULL) {
			smoother_pcr_alloc(&ctx->smoother, ctx, &smoother_pcr_cb, 5000, 1316, ctx->pcrPID, ctx->latencyMS);
		} else
		if (ctx->isRTP == 1 && ctx->sm == NULL && ctx->smoother == NULL) {
			smoother_rtp_alloc(&ctx->smoother, ctx, &smoother_rtp_cb, 5000, 12 + (7 * 188), ctx->latencyMS);
		}

		/* UDP-TS only */
		if (ctx->isRTP == 0 && ctx->sm && ctx->smcomplete == 0 && ctx->pcrPID == 0) {

			ltntstools_streammodel_write(ctx->sm, &buf[boffset], rlen / 188, &ctx->smcomplete);

			if (ctx->smcomplete) {
				struct ltntstools_pat_s *pat = NULL;
				if (ltntstools_streammodel_query_model(ctx->sm, &pat) == 0) {

					/* Walk all the services, find the first service PMT. */
					int e = 0;
					struct ltntstools_pmt_s *pmt;
					uint16_t videopid = 0;

					while (ltntstools_pat_enum_services_video(pat, &e, &pmt) == 0) {

						uint8_t estype;
						ltntstools_pmt_query_video_pid(pmt, &videopid, &estype);

						char ts[256];
						time_t now = time(0);
						sprintf(ts, "%s", ctime(&now));
						ts[ strlen(ts) - 1] = 0;

						printf("%s: Found program %5d, PCR pid 0x%04x, video pid 0x%04x\n",
							ts,
							pmt->program_number,
							pmt->PCR_PID,
							videopid);

						ctx->pcrPID = pmt->PCR_PID;
						break; /* TODO: We only support the first VIDEO pid (SPTS) */
					}

					if (ctx->verbose > 1) {
						ltntstools_pat_dprintf(pat, 0);
					}

					if (ctx->pcrPID == 0) {
						printf("\nNo VIDEO/PCR_PID PID detected, terminating\n\n");
						gRunning = 0; /* Terminate */
						//ltntstools_pat_dprintf(pat, 0);
					} else {
						smoother_pcr_alloc(&ctx->smoother, ctx, &smoother_pcr_cb, 5000, 1316, ctx->pcrPID, ctx->latencyMS);
					}
					ltntstools_pat_free(pat);
				}
			}
		}

		lastPacketTime = now;

		/* Pass the transport packets ONLY to the stats collector, don't pass RTP headers */
		packet_cb(ctx, &buf[boffset], rlen - boffset);

		if (ctx->isRTP == 0 && ctx->smoother) {
			smoother_pcr_write(ctx->smoother, buf, rlen, NULL);
		}
		if (ctx->isRTP == 1 && ctx->smoother) {

			/* Dump the packet hex */
			if (ctx->verbose & 8) {
				print_rtp_buffer(ctx, buf, rlen);
			}

			/* Monitor for RTP sequence problems. Assumes the buffer starts with the RTP header. */
			rtp_hdr_write(&ctx->rtp_stream_in, (struct rtp_hdr *)buf);

			/* Feed the smoother */
			smoother_rtp_write(ctx->smoother, buf, rlen, NULL);
		}

	}
	ctx->ffmpeg_threadTerminated = 1;
	free(buf);

	pthread_exit(0);
	return 0;
}

static void signal_handler(int signum)
{
	gRunning = 0;
}

static void kernel_check_socket_sizes(AVIOContext *i)
{
	printf("Kernel configured default/max socket buffer sizes:\n");

	char line[256];
	int val;
	FILE *fh = fopen("/proc/sys/net/core/rmem_default", "r");
	if (fh) {
		fread(&line[0], 1, sizeof(line), fh);
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_default = %d\n", val);
		fclose(fh);
	}

	fh = fopen("/proc/sys/net/core/rmem_max", "r");
	if (fh) {
		fread(&line[0], 1, sizeof(line), fh);
		val = atoi(line);
		printf("/proc/sys/net/core/rmem_max = %d\n", val);
		if (i->buffer_size > val) {
			fprintf(stderr, "buffer_size %d exceeds rmem_max %d, aborting\n", i->buffer_size, val);
			exit(1);
		}
		fclose(fh);
	}

}

#ifdef __linux__
static void timer_thread(union sigval arg)
{
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
	printf("A tool to smooth input RTP-TS and UDP-TS CBR bitrate MPEG-TS streams.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp|rtp://234.1.1.1:4160?localaddr=172.16.0.67\n");
	printf("           172.16.0.67 is the IP addr where we'll issue an IGMP join\n");
	printf("  -o <url> Eg: udp|rtp://234.1.1.1:4560\n");
	printf("  -P 0xnnnn PID containing the PCR (UDP-TS Only. Optional)\n");
	printf("  -v # bitmask. Set level of verbosity. [def: 0]\n");
	printf("     1 - input packet hex\n");
	printf("     2 - output packet hex\n");
	printf("     4 - output packet PCR data and human readable PCR clock\n");
	printf("     8 - input packet RTP data and human readable clock\n");
	printf("  -R pid 0xNNNN to be removed [def: none], multiple -R instances supported. [0x2000 all pids]\n");
	printf("  -l latency (ms) of protection. [def: %d]\n", DEFAULT_LATENCY);
#ifdef __linux__
	printf("  -t <#seconds> Stop after N seconds [def: 0 - unlimited]\n");
#endif
	printf("  -L <#seconds> During input LOS, terminate software after time. [def: 0 - don't terminate]\n");
	printf("  -h Display command line help.\n");
	printf("\n  Example UDP or RTP, don't mix'n'match:\n");
	printf("    tstools_bitrate_smoother -i 'udp://227.1.20.80:4002?localaddr=192.168.20.45&buffer_size=250000' \\\n");
	printf("      -o udp://227.1.20.45:4501?pkt_size=1316 -l 500\n");
	printf("\n    tstools_bitrate_smoother -i 'rtp://227.1.20.80:4002?localaddr=192.168.20.45&buffer_size=250000' \\\n");
	printf("      -o rtp://227.1.20.45:4501?pkt_size=1328 -l 500\n");
}

int bitrate_smoother(int argc, char *argv[])
{
	int ret = 0;
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));
	memset(&ctx->filter[0], 1, sizeof(ctx->filter)); /* Pass all pids by default */

	ctx->latencyMS = DEFAULT_LATENCY;
	ctx->reframer = ltntstools_reframer_alloc(ctx, 7 * 188, (ltntstools_reframer_callback)reframer_cb);

	ltntstools_pid_stats_alloc(&ctx->i_stream);
	ltntstools_pid_stats_alloc(&ctx->o_stream);

	while ((ch = getopt(argc, argv, "?hi:l:o:L:P:R:v:t:")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case 'l':
			ctx->latencyMS = atoi(optarg);
			break;
		case 'i':
			ctx->iname = optarg;
			break;
		case 'v':
			ctx->verbose = atoi(optarg);
			break;
		case 'o':
			ctx->oname = optarg;
			break;
		case 'L':
			ctx->terminateLOSSeconds = atoi(optarg);
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &ctx->pcrPID) != 1) || (ctx->pcrPID > 0x1fff)) {
					usage(argv[0]);
					exit(1);
			}
			break;
		case 'R':
			if ((sscanf(optarg, "0x%x", &ctx->pid) != 1) || (ctx->pid > 0x2000)) {
				usage(argv[0]);
				exit(1);
			}
			if (ctx->pid == 0x2000) {
				memset(&ctx->filter[0], 0, sizeof(ctx->filter)); /* Disable all pids by default */
			} else {
				ctx->filter[ ctx->pid ] = 0; /* Disable pid output */
			}
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
		fprintf(stderr, "\n-i is mandatory, aborting.\n\n");
		exit(1);
	}

	if (ctx->oname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-o is mandatory, aborting.\n\n");
		exit(1);
	}

	if (ctx->terminateLOSSeconds) {
		printf("\n-L %d, process will self terminate if input LOS exceeds %d seconds.\n\n", ctx->terminateLOSSeconds, ctx->terminateLOSSeconds);
	}

	if (ctx->stopAfterSeconds) {
#ifdef __linux__
		terminate_after_seconds(ctx, ctx->stopAfterSeconds);
#endif
	}

	if (strcasestr(ctx->iname, "rtp:")) {
		ctx->isRTP = 1;
		rtp_analyzer_init(&ctx->rtp_stream_in);
		rtp_analyzer_init(&ctx->rtp_stream_out);
	}

	avformat_network_init();
	
	ret = avio_open2(&ctx->i_puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		ret = -1;
		goto no_output;
	}

	ret = avio_open2(&ctx->o_puc, ctx->oname, AVIO_FLAG_WRITE | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "-o syntax error\n");
		ret = -1;
		goto no_output;
	}

	kernel_check_socket_sizes(ctx->i_puc);

	if (ctx->pid != 0) {
		int cnt = 0;
		for (int i = 0; i < 8192; i++) {
			if (ctx->filter[i] == 0) {
				cnt++;
			}
		}
		printf("\nBlocking %d pids:\n", cnt);
		for (int i = 0; i < 8192; i++) {
			if (ctx->filter[i] == 0) {
				printf("0x%04x (%05d), ", i, i);
			}
		}
		printf("\n\n");

	}
	/* Preallocate enough throughput measures for approx a 40mbit stream */
	signal(SIGINT, signal_handler);
	gRunning = 1;

	pthread_create(&ctx->ffmpeg_threadId, 0, thread_packet_rx, ctx);

	signal(SIGINT, signal_handler);
	while (gRunning) {
		usleep(50 * 1000);
	}

	/* Shutdown ffmpeg */
	ctx->ffmpeg_threadTerminate = 1;
	while (!ctx->ffmpeg_threadTerminated)
		usleep(50 * 1000);

	avio_close(ctx->i_puc);
	avio_close(ctx->o_puc);

	if (ctx->isRTP == 0) {
		if (ctx->smoother) {
			smoother_pcr_free(ctx->smoother);
			ctx->smoother = 0;
		}
	} else {
		if (ctx->smoother) {
			smoother_rtp_free(ctx->smoother);
			ctx->smoother = 0;
		}
	}
	ctx->smoother = 0;

	ltntstools_reframer_free(ctx->reframer);

	if (ctx->sm) {
		ltntstools_streammodel_free(ctx->sm);
	}

	ret = 0;

	if (ctx->iname)
		printf("\nInput from %s\n", ctx->iname);
	if (ctx->oname)
		printf("Output  to %s\n", ctx->oname);

	int64_t errCount = 0;

	if (ctx->isRTP) {
		rtp_analyzer_report_dprintf(&ctx->rtp_stream_in, STDOUT_FILENO);
	}

	printf("\nI: PID   PID     PacketCount   CCErrors  TEIErrors\n");
	printf("----------------------------  --------- ----------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->i_stream->pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n", i, i,
				ctx->i_stream->pids[i].packetCount,
				ctx->i_stream->pids[i].ccErrors,
				ctx->i_stream->pids[i].teiErrors);
			errCount += ctx->i_stream->pids[i].ccErrors;
		}
	}

	if (ctx->isRTP) {
		rtp_analyzer_report_dprintf(&ctx->rtp_stream_out, STDOUT_FILENO);
	}
	printf("O: PID   PID     PacketCount   CCErrors  TEIErrors\n");
	printf("----------------------------  --------- ----------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->o_stream->pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n", i, i,
				ctx->o_stream->pids[i].packetCount,
				ctx->o_stream->pids[i].ccErrors,
				ctx->o_stream->pids[i].teiErrors);
			errCount += ctx->o_stream->pids[i].ccErrors;
		}
	}

	ltntstools_pid_stats_free(ctx->i_stream);
	ltntstools_pid_stats_free(ctx->o_stream);

	if (ctx->isRTP) {
		rtp_analyzer_free(&ctx->rtp_stream_in);
		rtp_analyzer_free(&ctx->rtp_stream_out);
	}

	ret = 0;

no_output:
	return ret;
}
