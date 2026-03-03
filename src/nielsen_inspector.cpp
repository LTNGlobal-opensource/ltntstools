// ./tstools_nielsen_inspector -i 'udp://227.1.20.80:4001?buffer_size=16384000&fifo_size=8192000&overrun_nonfatal=1' -N
// sudo sysctl -w net.core.rmem_default=16384000
// sudo sysctl -w net.core.rmem_max=16384000

#include <stdio.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <libltntstools/ltntstools.h>
#include "source-avio.h"
#include "audioanalyzer.h"

extern "C" {
#include <libavformat/avformat.h>
#include <libavutil/dict.h>
};

static int gRunning = 0;

static void signal_handler(int signum)
{
	gRunning = 0;
}

struct tools_ctx_s
{
	char *iname;
	int verbose;
	int nielsenDetection;

	void *aa;
};


static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount, struct timeval *capture_time)
{
	struct tools_ctx_s *ctx = (struct tools_ctx_s *)userContext;

	if (ctx->verbose >= 6) {
		printf("source received %d bytes\n", packetCount * 188);
	}

	ltntstools_audioanalyzer_write(ctx->aa, pkts, packetCount);

	return NULL;
}

static void *_avio_raw_callback_status(void *userContext, enum source_avio_status_e status)
{
	switch (status) {
	case AVIO_STATUS_MEDIA_START:
		printf("AVIO media starts\n");
		break;
	case AVIO_STATUS_MEDIA_END:
		printf("AVIO media ends\n");
		signal_handler(0);
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}

static void usage()
{
	printf("\nA tool to read nielsen audio watermarks from a live compressed UDP stream.\n");
	printf("Provide a detailed report of any detected codes.\n");
	printf("\nUsage:\n");
	printf("  -i <url> Eg: udp://234.1.1.1:4160?localaddr=172.16.0.67\n");
	printf("           172.16.0.67 is the IP addr where we'll issue a IGMP join\n");

	if (ltntstools_audioanalyzer_has_feature_nielsen(NULL)) {
		printf("  -N decode all audio streams and detect nielseon codes (available)\n");
	} else {
		printf("  -N decode all audio streams and detect nielseon codes (Unavailable)\n");
	}
	printf("\n");
	printf("  Examples:\n");
	printf("    -i 'udp://227.1.20.80:4001?buffer_size=16384000&fifo_size=8192000&overrun_nonfatal=1' -N\n");
	printf("        -- decode all audio tracks (Stereo only) and display for Nielsen codes (wait for 120 seconds)\n");
}

int _nielsen_inspector(int argc, char **argv)
{
	struct tools_ctx_s lctx, *ctx = &lctx;
	memset(&lctx, 0, sizeof(lctx));
	ctx->nielsenDetection = 1;

	int ch;
	while ((ch = getopt(argc, argv, "?hi:Nv")) != -1) {
		switch(ch) {
		case 'i':
			ctx->iname = strdup(optarg);
			break;
		case 'N':
			if (ltntstools_audioanalyzer_has_feature_nielsen(NULL))
				ctx->nielsenDetection = 1;
			break;
		case 'v':
			ctx->verbose++;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (ctx->iname == NULL) {
		usage();
		fprintf(stderr, "\n-i is mandatory, aborting\n\n");
		exit(1);
	}

	if (ltntstools_audioanalyzer_has_feature_nielsen(NULL) == 0) {
		printf("No Nielsen audio decoder detected, this build does not include Nielsen support, aborting.\n");
		exit(1);
	}

	printf("\nEnabling the Nielsen decoder\n\n");
	int ret = ltntstools_audioanalyzer_alloc(&ctx->aa);
	if (ret != 0) {
		fprintf(stderr, "Unable to allocate the audioanalyzer framework\n");
		exit(1);
	}
	ltntstools_audioanalyzer_set_verbosity(ctx->aa, ctx->verbose);

	/* Quiet the ffmpeg stack, we don't care about parsing errors on startup. */
	av_log_set_level(AV_LOG_QUIET);

	AVFormatContext *fmt_ctx = NULL;
	if ((ret = avformat_open_input(&fmt_ctx, ctx->iname, NULL, NULL))) {
		fprintf(stderr, "\nUnable to open input '%s', aborting.\n\n", ctx->iname);
		return ret;
	}

	/* Read stream, analyze codecs etc. */
	ret = avformat_find_stream_info(fmt_ctx, 0);
	if (ret < 0) {
		fprintf(stderr, "Unable to obtain stream information, aborting.\n");
		return ret;
	}

	/* Turn up verbosity, we want ffmpeg dump to report to console. */
	av_log_set_level(AV_LOG_INFO);

	/* in hidden dev mode, manually report some values after the probe is complete,
	 * developer experimental, not used by default.
	 */
	const AVInputFormat *ifmt = fmt_ctx->iformat;

	printf("  ->input   : %s:\n", ifmt->long_name);
	printf("  ->nb_programs = %d (%s)\n", fmt_ctx->nb_programs, fmt_ctx->nb_programs == 1 ? "SPTS" : "MPTS");
	for (unsigned int i = 0; i < fmt_ctx->nb_programs; i++) {
		AVProgram *p = fmt_ctx->programs[i];
		printf("    [%02d] pmt_pid 0x%04x pcr_pid 0x%04x\n", p->program_num, p->pmt_pid, p->pcr_pid);
	}

	printf("    ->nb_streams = %d\n", fmt_ctx->nb_streams);
	printf("       NN      PID    Type   Codec Width Height  Framerate Channels Format   Rate  Bitrate\n");
	for (unsigned int i = 0; i < fmt_ctx->nb_streams; i++) {
		AVStream *s = fmt_ctx->streams[i];
		AVCodecParameters *codec = s->codecpar;

		printf("      [%02d]  0x%04x ", s->index, s->id);
		printf("%7s ", av_get_media_type_string(codec->codec_type));
		printf("%7s ", avcodec_get_name(codec->codec_id));

		if (codec->codec_type == AVMEDIA_TYPE_VIDEO) {
			printf("%5d ", codec->width);
			printf("%6d ", codec->height);
			float fps = (float)s->avg_frame_rate.num / (float)s->avg_frame_rate.den;
			printf(" %.2f { %6d, %4d } ", fps, s->avg_frame_rate.num, s->avg_frame_rate.den);
		} else
		if (codec->codec_type == AVMEDIA_TYPE_AUDIO) {
			printf("%32d ", codec->channels);
			printf("%6s ", av_get_sample_fmt_name((AVSampleFormat)codec->format));
			printf("%6d ", codec->sample_rate);
			printf("%8" PRIi64, codec->bit_rate / 1000);

			if (ctx->nielsenDetection) {
				uint8_t streamID;
				switch (codec->codec_id) {
				case AV_CODEC_ID_AC3:
					streamID = 0xBD;
					break;
				case AV_CODEC_ID_MP2:
					streamID = 0xC0;
					break;
				default:
				case AV_CODEC_ID_AAC:
					streamID = 0xC0;
					break;
				}
				/* make a note of which audio pids we want to monitor and their codec types */
				/* We only support S16P currently, so go ahead and try this... */
				ret = ltntstools_audioanalyzer_stream_add(ctx->aa, s->id, streamID, codec->codec_id, AV_SAMPLE_FMT_S16P, 1 /* Enable Nielsen */);
				if (ret != 0) {
					fprintf(stderr, "Unable to add stream to decoder\n");
				}
			}

		}
		printf("\n");
#if 0
		AVDictionaryEntry *tag = NULL;
		while ((tag = av_dict_get(s->metadata, "", tag, AV_DICT_IGNORE_SUFFIX))) {
			printf("%s=%s\n", tag->key, tag->value);
		}
#endif
	}
	printf("\n");

	printf("Be patient, this can take 90 seconds or so...\n\n");
	printf("Reading %s\n", ctx->iname);

	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;

	void *srcctx = NULL;
	ret = ltntstools_source_avio_alloc(&srcctx, ctx, &cbs, ctx->iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	signal(SIGINT, signal_handler);
	gRunning = 1;

	while (gRunning) {
		usleep(50 * 1000);
	}
	printf("Terminating....\n");

	ltntstools_source_avio_free(srcctx);

	//avformat_close_input(&fmt_ctx);  segfault in this
#if LOCAL_DEBUG
	printf("Freeing audio decoder\n");
#endif
	ltntstools_audioanalyzer_free(ctx->aa);

	free(ctx->iname);
	return 0;
}

extern "C" {
int nielsen_inspector(int argc, char **argv)
{
	return _nielsen_inspector(argc, argv);
}
};
