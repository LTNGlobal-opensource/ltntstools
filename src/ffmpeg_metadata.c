// ./tstools_ffmpeg_metadata -i udp://227.1.20.80:4001?buffer_size=8192000\&fifo_size=8192000 -N
// sudo sysctl -w net.core.rmem_default=8192000

#include <stdio.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <libltntstools/ltntstools.h>
#include <libavformat/avformat.h>
#include <libavutil/dict.h>

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

static void usage()
{
	printf("\nA tool to read video/audio metadata from a file.\n");
	printf("Provide a detailed report of the codecs and content.\n");
	printf("\nUsage:\n");
	printf("  -i <input.ts | input.pcap>\n");

	if (ltntstools_audioanalyzer_has_feature_nielsen(NULL)) {
		printf("  -N decode all audio streams and detect nielseon codes (available)\n");
	} else {
		printf("  -N decode all audio streams and detect nielseon codes (Unavailable)\n");
	}
}

int ffmpeg_metadata(int argc, char **argv)
{
	struct tools_ctx_s lctx = { 0 }, *ctx = &lctx;

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

	if (ctx->nielsenDetection) {
		printf("\nEnabling the Nielsen decoder\n");
		int ret = ltntstools_audioanalyzer_alloc(&ctx->aa);
		if (ret != 0) {
			fprintf(stderr, "Unable to allocate the audioanalyzer framework\n");
			exit(1);
		}
		ltntstools_audioanalyzer_set_verbosity(ctx->aa, ctx->verbose);
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

	if (!ctx->verbose && !ctx->nielsenDetection)
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
		printf("    [%02d] pmt_pid 0x%04x\n", p->program_num, p->pmt_pid);
		printf("         pcr_pid 0x%04x\n", p->pcr_pid);
	}

	printf("    ->nb_streams = %d\n", fmt_ctx->nb_streams);
	for (int i = 0; i < fmt_ctx->nb_streams; i++) {
		AVStream *s = fmt_ctx->streams[i];
		AVCodecParameters *codec = s->codecpar;

		printf("      [%02d]         pid = 0x%04x\n", s->index, s->id);
		printf("            codec_type = %s\n", av_get_media_type_string(codec->codec_type));
		printf("                 codec = %s\n", avcodec_get_name(codec->codec_id));

		if (codec->codec_type == AVMEDIA_TYPE_VIDEO) {
			printf("                 width = %d\n", codec->width);
			printf("                height = %d\n", codec->height);
			float fps = (float)s->avg_frame_rate.num / (float)s->avg_frame_rate.den;
			printf("            frame_rate = %.2f { %d, %d }\n", fps, s->avg_frame_rate.num, s->avg_frame_rate.den);
		} else
		if (codec->codec_type == AVMEDIA_TYPE_AUDIO) {
			printf("              channels = %d\n", codec->channels);
			printf("                format = %d [%s]\n", codec->format, av_get_sample_fmt_name(codec->format));
			printf("            samplerate = %d\n", codec->sample_rate);
			printf("              bit_rate = %" PRIi64 "kbps\n", codec->bit_rate / 1000);

			if (ctx->nielsenDetection) {
				/* make a note of which audio pids we want to monitor and their codec types */
				ret = ltntstools_audioanalyzer_stream_add(ctx->aa, s->id, 0xC0, codec->codec_id);
				if (ret != 0) {
					fprintf(stderr, "Unable to add stream to decoder\n");
				}
				printf("Finished adding stream\n");
			}

		}

		AVDictionaryEntry *tag = NULL;
		while ((tag = av_dict_get(s->metadata, "", tag, AV_DICT_IGNORE_SUFFIX))) {
			printf("%s=%s\n", tag->key, tag->value);
		}

	}

	AVDictionaryEntry *tag = NULL;
	while ((tag = av_dict_get(fmt_ctx->metadata, "", tag, AV_DICT_IGNORE_SUFFIX))) {
		printf("%s=%s\n", tag->key, tag->value);
	}

	if (ctx->nielsenDetection) {
		/* Listen to the entire transport stream, push it all into the audio decoder framework.
		 * The latency of feedinto to the audiodecoder isn't that important. The output of the audio
		 * decoder isn't anything we'll listen to, it's data that we'll further analyze for
		 * remote inspection.
		 */
		avformat_network_init();

		AVIOContext *i_puc = NULL;

		printf("Reading %s\n", ctx->iname);
		ret = avio_open2(&i_puc, ctx->iname, AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK | AVIO_FLAG_DIRECT, NULL, NULL);
		if (ret < 0) {
			fprintf(stderr, "-i syntax error\n");
			exit(1); /* how does this happen? */
		}

		int blen = 64 * 188;
		unsigned char *buf = malloc(blen);

		signal(SIGINT, signal_handler);
		gRunning = 1;

		while (gRunning) {
			int rlen = avio_read(i_puc, buf, blen);
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

			if (ctx->verbose >= 6) {
				printf("source received %d bytes\n", rlen);
			}

			if (rlen > 0) {
				ltntstools_audioanalyzer_write(ctx->aa, &buf[0], rlen / 188);
			}
		}
		printf("Terminating....\n");

		avio_close(i_puc);
	}

	//avformat_close_input(&fmt_ctx);  segfault in this
#if LOCAL_DEBUG
	printf("Freeing audio decoder\n");
#endif
	ltntstools_audioanalyzer_free(ctx->aa);

	return 0;
}
