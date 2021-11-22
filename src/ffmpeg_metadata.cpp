#include <stdio.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <libltntstools/ltntstools.h>

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
};

static void usage()
{
	printf("\nA tool to read video/audio metadata from a file.\n");
	printf("Provide a detailed report of the codecs and content.\n");
	printf("\nUsage:\n");
	printf("  -i <input.ts | input.pcap>\n");
	printf("\n");
}

int _ffmpeg_metadata(int argc, char **argv)
{
	struct tools_ctx_s lctx, *ctx = &lctx;
	memset(&lctx, 0, sizeof(lctx));

	int ch;
	while ((ch = getopt(argc, argv, "?hi:v")) != -1) {
		switch(ch) {
		case 'i':
			ctx->iname = strdup(optarg);
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

#ifdef __linux__
	av_register_all();
#endif

	/* Quiet the ffmpeg stack, we don't care about parsing errors on startup. */
	av_log_set_level(AV_LOG_QUIET);

	int ret;
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
	printf("\n");
	av_dump_format(fmt_ctx, 0, ctx->iname, 0);
	printf("\n");

	if (!ctx->verbose)
		return 0; /* Yes, we leak, that's ok. */

	/* in hidden dev mode, manually report some values after the probe is complete,
	 * developer experimental, not used by default.
	 */
	const AVInputFormat *ifmt = fmt_ctx->iformat;

	printf("  ->input   : %s:\n", ifmt->long_name);
	printf("  ->metadata: %p:\n", fmt_ctx->metadata);
	printf("  ->nb_programs = %d\n", fmt_ctx->nb_programs);
	for (int i = 0; i < fmt_ctx->nb_programs; i++) {
		AVProgram *p = fmt_ctx->programs[i];
		printf("    [%02d] pmt_pid 0x%04x pcr_pid 0x%04x\n", p->program_num, p->pmt_pid, p->pcr_pid);
	}

	printf("    ->nb_streams = %d\n", fmt_ctx->nb_streams);
	printf("       NN      pid    type   codec width height  framerate channels    fmt   rate  bitrate\n");
	for (int i = 0; i < fmt_ctx->nb_streams; i++) {
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
		}
		printf("\n");

		AVDictionaryEntry *tag = NULL;
		while ((tag = av_dict_get(s->metadata, "", tag, AV_DICT_IGNORE_SUFFIX))) {
			printf("%s=%s\n", tag->key, tag->value);
		}

	}

	AVDictionaryEntry *tag = NULL;
	while ((tag = av_dict_get(fmt_ctx->metadata, "", tag, AV_DICT_IGNORE_SUFFIX))) {
		printf("%s=%s\n", tag->key, tag->value);
	}

	return 0;
}

extern "C" {
int ffmpeg_metadata(int argc, char **argv)
{
	return _ffmpeg_metadata(argc, argv);
}
};
