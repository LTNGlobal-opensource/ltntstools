#include <stdio.h>
#include <getopt.h>
#include <libavformat/avformat.h>
#include <libavutil/dict.h>

static void usage()
{
	printf("\nA tool to read video/audio metadata from a file.\n");
	printf("Provide a detailed report of the codecs and content.\n");
	printf("\nUsage:\n");
	printf("  -i <input.ts | input.pcap>\n");
}

int ffmpeg_metadata(int argc, char **argv)
{
	char *iname = NULL;
	int verbose = 0;

	int ch;
	while ((ch = getopt(argc, argv, "?hi:v")) != -1) {
		switch(ch) {
		case 'i':
			iname = strdup(optarg);
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (iname == NULL) {
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
	if ((ret = avformat_open_input(&fmt_ctx, iname, NULL, NULL))) {
		fprintf(stderr, "\nUnable to open input '%s', aborting.\n\n", iname);
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
	av_dump_format(fmt_ctx, 0, iname, 0);
	printf("\n");

	if (!verbose)
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

		printf("      [%02d]  codec_type = %s\n", s->index, av_get_media_type_string(codec->codec_type));
		printf("                 codec = %s\n", avcodec_get_name(codec->codec_id));

		if (codec->codec_type == AVMEDIA_TYPE_VIDEO) {
			printf("                 width = %d\n", codec->width);
			printf("                height = %d\n", codec->height);
			float fps = (float)s->avg_frame_rate.num / (float)s->avg_frame_rate.den;
			printf("            frame_rate = %.2f { %d, %d }\n", fps, s->avg_frame_rate.num, s->avg_frame_rate.den);
		} else
		if (codec->codec_type == AVMEDIA_TYPE_AUDIO) {
			printf("              channels = %d\n", codec->channels);
			printf("            samplerate = %d\n", codec->sample_rate);
			printf("              bit_rate = %" PRIi64 "kbps\n", codec->bit_rate / 1000);
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

	avformat_close_input(&fmt_ctx);
	return 0;
}
