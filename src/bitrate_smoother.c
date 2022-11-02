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
#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "kbhit.h"

#define DEFAULT_FIFOSIZE 1048576
#define DEFAULT_TRAILERROW 18
#define DEFAULT_LATENCY 100

#define ENABLE_PIR_CORRECTOR 0

#if ENABLE_PIR_CORRECTOR

#include "klbitstream_readwriter.h"

const unsigned char nal[] = {

#if 0
	/* sps */
	0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x0a, 0xf8, 0x41, 0xa2,

	/* see 14496-10 7/3/2/2 - pic_parameter_set_rbsp */
	0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x38, 0x80,
#endif
	/* Slice header */
	0x00, 0x00, 0x00, 0x01, 0x05, 0x88, 0x84, 0x21, 0xa0, 
	
	/* One I_PCM 16x16 macroblock. 384 bytes which is 16x16x1.5 for luma and chroma. */
	0x27, 0x28, 0x28, 0x2a,
	0x2b, 0x28, 0x14, 0x11, 0x11, 0x17, 0x19, 0x19, 0x1f, 0x21, 0x13, 0x11, 0x28, 0x28, 0x29, 0x2c,
	0x2d, 0x2a, 0x13, 0x10, 0x11, 0x17, 0x19, 0x18, 0x1b, 0x1a, 0x11, 0x0f, 0x29, 0x29, 0x29, 0x2b,
	0x2b, 0x28, 0x12, 0x10, 0x10, 0x17, 0x1a, 0x19, 0x18, 0x16, 0x13, 0x10, 0x2c, 0x2c, 0x2c, 0x2d,
	0x2b, 0x27, 0x12, 0x10, 0x11, 0x19, 0x1b, 0x1a, 0x18, 0x15, 0x18, 0x16, 0x2b, 0x29, 0x2b, 0x2d,
	0x2c, 0x26, 0x12, 0x10, 0x10, 0x20, 0x28, 0x29, 0x2a, 0x18, 0x1c, 0x1d, 0x29, 0x28, 0x29, 0x2c,
	0x2b, 0x24, 0x11, 0x10, 0x10, 0x35, 0x45, 0x46, 0x47, 0x1f, 0x1a, 0x24, 0x2a, 0x29, 0x29, 0x2b,
	0x29, 0x22, 0x10, 0x0f, 0x11, 0x42, 0x4e, 0x45, 0x3f, 0x1c, 0x17, 0x2a, 0x2a, 0x29, 0x28, 0x29,
	0x28, 0x23, 0x10, 0x10, 0x12, 0x32, 0x34, 0x32, 0x2c, 0x19, 0x15, 0x2f, 0x2b, 0x29, 0x28, 0x27,
	0x28, 0x22, 0x10, 0x10, 0x11, 0x1a, 0x36, 0x62, 0x65, 0x3d, 0x10, 0x27, 0x2c, 0x2a, 0x29, 0x28,
	0x28, 0x21, 0x10, 0x10, 0x10, 0x16, 0x3f, 0x7a, 0x7b, 0x55, 0x12, 0x1f, 0x2c, 0x29, 0x29, 0x27,
	0x27, 0x20, 0x10, 0x10, 0x10, 0x15, 0x35, 0x5a, 0x56, 0x3c, 0x13, 0x1e, 0x2b, 0x29, 0x29, 0x27,
	0x27, 0x1d, 0x10, 0x10, 0x11, 0x14, 0x25, 0x36, 0x2f, 0x1d, 0x12, 0x1c, 0x27, 0x28, 0x29, 0x27,
	0x26, 0x1b, 0x10, 0x10, 0x11, 0x13, 0x19, 0x26, 0x26, 0x1c, 0x0f, 0x17, 0x27, 0x27, 0x29, 0x28,
	0x23, 0x18, 0x0f, 0x10, 0x10, 0x12, 0x16, 0x20, 0x23, 0x1b, 0x0f, 0x11, 0x28, 0x26, 0x29, 0x28,
	0x21, 0x16, 0x0f, 0x10, 0x10, 0x11, 0x13, 0x16, 0x16, 0x13, 0x10, 0x13, 0x27, 0x27, 0x28, 0x28,
	0x21, 0x15, 0x10, 0x10, 0x10, 0x11, 0x12, 0x17, 0x1a, 0x13, 0x0f, 0x1b, 0x79, 0x78, 0x77, 0x7e,
	0x89, 0x92, 0x8a, 0x80, 0x76, 0x76, 0x77, 0x7e, 0x8a, 0x9b, 0x85, 0x7d, 0x78, 0x76, 0x78, 0x7d,
	0x90, 0xb0, 0x9b, 0x7a, 0x77, 0x78, 0x79, 0x7c, 0x95, 0xb2, 0x99, 0x7b, 0x76, 0x79, 0x7a, 0x7e,
	0x8d, 0x8b, 0x7f, 0x7e, 0x77, 0x79, 0x7a, 0x7e, 0x8a, 0x84, 0x7c, 0x7f, 0x78, 0x78, 0x7b, 0x7e,
	0x88, 0x84, 0x7d, 0x7f, 0x78, 0x78, 0x7c, 0x7f, 0x84, 0x81, 0x7c, 0x83, 0x86, 0x87, 0x88, 0x81,
	0x7e, 0x7b, 0x83, 0x82, 0x87, 0x87, 0x86, 0x81, 0x7d, 0x79, 0x82, 0x83, 0x87, 0x87, 0x86, 0x81,
	0x76, 0x61, 0x70, 0x85, 0x86, 0x87, 0x86, 0x81, 0x70, 0x60, 0x73, 0x86, 0x86, 0x86, 0x86, 0x80,
	0x7b, 0x85, 0x8b, 0x84, 0x87, 0x86, 0x85, 0x7f, 0x7e, 0x85, 0x85, 0x81, 0x87, 0x86, 0x84, 0x7f,
	0x7e, 0x80, 0x80, 0x80, 0x86, 0x87, 0x83, 0x7f, 0x7f, 0x81, 0x84, 0x7b,
	0x80 /* Slice Stop Bit */
};
#endif

static int gRunning = 0;

struct tool_context_s
{
	char *iname, *oname;
	int verbose;
	int stopAfterSeconds;
	int terminateLOSSeconds;

	struct ltntstools_stream_statistics_s i_stream, o_stream;
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
	int pcrPID;

#if ENABLE_PIR_CORRECTOR
	struct {
		uint8_t video_NextCC;
		uint16_t vpid;
		time_t lastInject;
	} pc;
#endif

	struct ltntstools_reframer_ctx_s *reframer;

	void *sm; /* StreamModel Context */
	int smcomplete;

};

static void *reframer_cb(void *userContext, const uint8_t *buf, int lengthBytes)
{
	struct tool_context_s *ctx = userContext;
	avio_write(ctx->o_puc, buf, lengthBytes);
	return NULL;
}

static void transmit_packets(struct tool_context_s *ctx, unsigned char *pkts, int packetCount)
{
#if ENABLE_PIR_CORRECTOR
	printf("Sending %d\n", packetCount);

	unsigned char *buf = malloc(7 * 188);
	for (int i = 0; i < 7; i++) {
		ltntstools_generateNullPacket(&buf[i * 188]);
	}

	memcpy(buf, pkts, packetCount * 188);

	printf("Sending %d/%d packets : \n\t", packetCount, 7 - packetCount);
	for (int j = 0; j < 7; j++) {
		unsigned char *pkt = buf + (j * 188);
		for (int i = 0; i < 8; i++)
			printf("%02x ", *(pkt + i));
		printf(" , ");
	}
	printf("\n");


	/* Find any video pids, and update their CC counters to remove any probelms due to inserts. */
	for (int i = 0; i < 7; i++) {
		uint16_t pidnr = ltntstools_pid(buf + (i * 188));

		if (pidnr != ctx->pc.vpid)
			continue;

		/* Update the video counters to be consecutive */
		unsigned char *p = buf + (i * 188) + 3;
		*p &= 0xf0;
		*p |= (ctx->pc.video_NextCC & 0x0f);

		ctx->pc.video_NextCC++;
	}

	avio_write(ctx->o_puc, buf, 7 * 188);
	free(buf);
#else
	ltststools_reframer_write(ctx->reframer, pkts, packetCount * 188);
#endif
}

static int smoother_cb(void *userContext, unsigned char *buf, int byteCount,
	struct ltntstools_pcr_position_s *array, int arrayLength)
{
	struct tool_context_s *ctx = userContext;
	
	if (ctx->verbose & 8) {
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
		struct ltntstools_pid_statistics_s *pid = &ctx->o_stream.pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = ltntstools_continuity_counter(buf + i);
		if (ltntstools_isCCInError(buf + i, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
				char ts[256];
				time_t now = time(0);
				sprintf(ts, "%s", ctime(&now));
				ts[ strlen(ts) - 1] = 0;
				printf("%s: CC Error : pid %04x -- Got 0x%x wanted 0x%x\n", ts, pidnr, cc, (pid->lastCC + 1) & 0x0f);
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

#if ENABLE_PIR_CORRECTOR


	/* Issue a video pid insertion every couple of seconds */

	/* Search the current buffer for a video pid with ltntstools_payload_unit_start_indicator() true */
	/* Output every packet up to that point. */

	/* The NAL is prebuilt. */
	/* Allocate a new PES, put the right PTS time in. */
	/* add the NAL to the pes */
	/* Container the PES into TS. */
	/* update the CC counters in the TS. */
	/* Inject the TS */
	/* Enjext the rest of the remaining origing input buffer. */

	time_t now = time(NULL);

	/* Index into buffer, if we've located a good place ti insert a new slice. */
	int PU_offset_pkt = -1;

	if (ctx->pc.lastInject + 1 <= now) {

		for (int i = 0; i < byteCount; i += 188) {
			uint8_t *pkt = buf + i;

			uint16_t pidnr = ltntstools_pid(pkt);
			if (pidnr != ctx->pc.vpid)
				continue;

			if (ltntstools_payload_unit_start_indicator(pkt) == 0)
				continue;

			/* Found a place to insert our new slice, before this packet. */
			PU_offset_pkt = i;
			break;
		}

		if (PU_offset_pkt == -1) {
			/* Wanted to insert new slice, coun't find an appropriate stream position,
			 * continue as normal and check during next callback.
			 */
		} else {
			ctx->pc.lastInject = now;

			/* Transmit all packets up to the new PUSI */
			printf("Sending head to  %d\n", PU_offset_pkt);
			transmit_packets(ctx, buf, PU_offset_pkt / 188);
#if 1
			/* Make a new PES, appaend our new NAL. */
			struct ltn_pes_packet_s *pes = ltn_pes_packet_alloc();

			pes->packet_start_code_prefix	= 1;
			pes->stream_id					= 0xe0;
			pes->PES_packet_length			= 3 + sizeof(nal);
			pes->PES_scrambling_control		= 0;
			pes->PES_priority				= 1;
			pes->data_alignment_indicator	= 1;
			pes->copyright					= 1;
			pes->original_or_copy			= 1;
			pes->PTS_DTS_flags				= 0; //2;
			pes->ESCR_flag					= 0;
			pes->ES_rate_flag				= 0;
			pes->DSM_trick_mode_flag		= 0;
			pes->additional_copy_info_flag	= 0;
			pes->PES_CRC_flag				= 0;
			pes->PES_extension_flag			= 0;
			pes->PES_header_data_length		= 0;
			pes->dataLengthBytes            = sizeof(nal);
			pes->data						= malloc(pes->dataLengthBytes);
			memcpy(pes->data, nal, pes->dataLengthBytes);

			if (pes->PTS_DTS_flags == 2) {
				/* PTS only */
				pes->PTS = 5 * 90000;
				/* TODO, we need the next PTS for the current video slice, so the downstyream decoder decodes
				* this slice and an iframe, updates its macroblock, then immediately replaces the same macroblock
				* with the next immediate video frame.
				*/
			}

			/* We need a bitstream and a target buffer */
			int esbuflen = 512;
			unsigned char *esbuf = calloc(1, esbuflen);

			struct klbs_context_s *bs = klbs_alloc();
			klbs_write_set_buffer(bs, esbuf, esbuflen);

			/* Pack the pes into the bitstream */
			ssize_t bits = ltn_pes_packet_pack(pes, bs);

			for (int i = 0; i < 32; i++) {
				printf("%02x ", *(esbuf + i));
			}
			printf("\n");

			ltn_pes_packet_dump(pes, "");

			/* Packetize into TS */
			uint8_t *pkts;
			uint32_t packetCount;
			uint8_t cc = 0;
			ltntstools_ts_packetizer(esbuf, ((bits / 8) + 1), &pkts, &packetCount, 188, &cc, 0x31);

			for (int i = 0; i < 32; i++) {
				printf("%02x ", *(esbuf + i));
			}
			printf("\n");

			for (int i = 0; i < 32; i++) {
				printf("%02x ", *(pkts + i));
			}
			printf("\n");
	#if 0
			/* TODO: Round out the ts allocation to be a multiple of 7 packets.
			* this messes the PCR but keeps nic monitor happy during the
			* prototype phase.
			*/
			if (packetCount == 3) {
				pkts = realloc(pkts, 7 * 188);
				ltntstools_generateNullPacket(&pkts[3 * 188]);
				ltntstools_generateNullPacket(&pkts[4 * 188]);
				ltntstools_generateNullPacket(&pkts[5 * 188]);
				ltntstools_generateNullPacket(&pkts[6 * 188]);
				packetCount += 4;
			}
	#endif
			printf("Sending new slice\n");
			transmit_packets(ctx, pkts, packetCount);

			free(pkts);
			klbs_free(bs);
			free(esbuf);
			ltn_pes_packet_free(pes);
#endif
			/* Transmit all remaing packets from the original buffer */
			printf("Sending tail from %d\n", PU_offset_pkt);
			transmit_packets(ctx, buf + PU_offset_pkt, (byteCount - PU_offset_pkt) / 188);

		} /* if we're inserting */
		
	} /* If we're searching for an insert location */

	if (PU_offset_pkt == -1) {
		transmit_packets(ctx, buf, byteCount / 188);
	}

#else

	transmit_packets(ctx, buf, byteCount / 188);

#endif
	return 0;
}

static void *packet_cb(struct tool_context_s *ctx, unsigned char *buf, int byteCount)
{
	for (int i = 0; i < byteCount; i += 188) {
		uint16_t pidnr = ltntstools_pid(buf + i);
		struct ltntstools_pid_statistics_s *pid = &ctx->i_stream.pids[pidnr];

		pid->enabled = 1;
		pid->packetCount++;

		uint8_t cc = ltntstools_continuity_counter(buf + i);
		if (ltntstools_isCCInError(buf + i, pid->lastCC)) {
			if (pid->packetCount > 1 && pidnr != 0x1fff) {
				char ts[256];
				time_t now = time(0);
				sprintf(ts, "%s", ctime(&now));
				ts[ strlen(ts) - 1] = 0;
				printf("%s: CC Error : pid %04x -- Got 0x%x wanted 0x%x\n", ts, pidnr, cc, (pid->lastCC + 1) & 0x0f);
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

	unsigned char buf[7 * 188];

	time_t lastPacketTime = time(0);

	char ts[256];
	time_t now = time(0);
	sprintf(ts, "%s", ctime(&now));
	ts[ strlen(ts) - 1] = 0;
	printf("%s: Smoother starting\n", ts);

	while (!ctx->ffmpeg_threadTerminate) {
		int rlen = avio_read(ctx->i_puc, buf, sizeof(buf));
		if (ctx->verbose & 1) {
			printf("source received %d bytes\n", rlen);
		}
		now = time(0);
		if ((rlen == -EAGAIN) || (rlen == -ETIMEDOUT)) {
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

		/* Process the payload */

		if (ctx->sm == NULL && ctx->pcrPID == 0) {
			if (ltntstools_streammodel_alloc(&ctx->sm, NULL) < 0) {
				fprintf(stderr, "\nUnable to allocate streammodel object.\n\n");
				exit(1);
			}
		} else
		if (ctx->sm == NULL && ctx->pcrPID && ctx->smoother == NULL) {
			smoother_pcr_alloc(&ctx->smoother, ctx, &smoother_cb, 5000, 1316, ctx->pcrPID, ctx->latencyMS);
		}

		if (ctx->sm && ctx->smcomplete == 0 && ctx->pcrPID == 0) {

			ltntstools_streammodel_write(ctx->sm, &buf[0], rlen / 188, &ctx->smcomplete);

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
						smoother_pcr_alloc(&ctx->smoother, ctx, &smoother_cb, 5000, 1316, ctx->pcrPID, ctx->latencyMS);
					}
					ltntstools_pat_free(pat);
				}
			}
		}

		lastPacketTime = now;
		packet_cb(ctx, &buf[0], rlen);
		if (ctx->smoother) {
			smoother_pcr_write(ctx->smoother, buf, sizeof(buf), NULL);
		}

	}
	ctx->ffmpeg_threadTerminated = 1;

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
	printf("A tool to smooth input n*bps CBR bitrate to an output UDP stream.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: udp://234.1.1.1:4160?localaddr=172.16.0.67\n");
	printf("           172.16.0.67 is the IP addr where we'll issue an IGMP join\n");
	printf("  -o <url> Eg: udp://234.1.1.1:4560\n");
	printf("  -P 0xnnnn PID containing the PCR (Optional)\n");
	printf("  -v # bitmask. Set level of verbosity. [def: 0]\n");
	printf("     1 - input packet hex\n");
	printf("     2 - output packet hex\n");
	printf("     4 - output packet PCR data and human readable PCR clock\n");
	printf("  -l latency (ms) of protection. [def: %d]\n", DEFAULT_LATENCY);
#ifdef __linux__
	printf("  -t <#seconds> Stop after N seconds [def: 0 - unlimited]\n");
#endif
	printf("  -L <#seconds> During input LOS, terminate software after time. [def: 0 - don't terminate]\n");
	printf("  -h Display command line help.\n");
	printf("\n  Example:\n");
	printf("    tstools_bitrate_smoother -i 'udp://227.1.20.80:4002?localaddr=192.168.20.45&buffer_size=250000' \\\n");
	printf("      -o udp://227.1.20.45:4501?pkt_size=1316 -l 500\n");
}

int bitrate_smoother(int argc, char *argv[])
{
	int ret = 0;
	int ch;

	struct tool_context_s tctx, *ctx;
	ctx = &tctx;
	memset(ctx, 0, sizeof(*ctx));
	ctx->latencyMS = DEFAULT_LATENCY;
	ctx->reframer = ltntstools_reframer_alloc(ctx, 7 * 188, (ltntstools_reframer_callback)reframer_cb);

#if ENABLE_PIR_CORRECTOR
	ctx->pc.vpid = 0x31; /* TODO */
#endif

	while ((ch = getopt(argc, argv, "?hi:l:o:L:P:v:t:")) != -1) {
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

	smoother_pcr_free(ctx->smoother);
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

	printf("\nI: PID   PID     PacketCount   CCErrors  TEIErrors\n");
	printf("----------------------------  --------- ----------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->i_stream.pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n", i, i,
				ctx->i_stream.pids[i].packetCount,
				ctx->i_stream.pids[i].ccErrors,
				ctx->i_stream.pids[i].teiErrors);
			errCount += ctx->i_stream.pids[i].ccErrors;
		}
	}

	printf("O: PID   PID     PacketCount   CCErrors  TEIErrors\n");
	printf("----------------------------  --------- ----------\n");
	for (int i = 0; i < MAX_PID; i++) {	
		if (ctx->o_stream.pids[i].enabled) {
			printf("0x%04x (%4d) %14" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n", i, i,
				ctx->o_stream.pids[i].packetCount,
				ctx->o_stream.pids[i].ccErrors,
				ctx->o_stream.pids[i].teiErrors);
			errCount += ctx->o_stream.pids[i].ccErrors;
		}
	}

	ret = 0;

no_output:
	return ret;
}
