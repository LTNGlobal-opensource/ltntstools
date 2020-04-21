/*
 * Copyright (c) 2012 Stefano Sabatini
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * @file
 * Demuxing and decoding example.
 *
 * Show how to use the libavformat and libavcodec API to demux and
 * decode audio and video data.
 * @example demuxing_decoding.c
 */

#include <libavutil/imgutils.h>
#include <libavutil/samplefmt.h>
#include <libavutil/timestamp.h>
#include <libavformat/avformat.h>
#include <libltntstools/ltntstools.h>

static AVFormatContext *fmt_ctx = NULL;
static AVCodecContext *video_dec_ctx = NULL, *audio_dec_ctx;
static int width, height;
static enum AVPixelFormat pix_fmt;
static AVStream *video_stream = NULL, *audio_stream = NULL;
static const char *src_filename = NULL;
static const char *video_dst_filename = NULL;
static const char *audio_dst_filename = NULL;
static FILE *video_dst_file = NULL;
static FILE *audio_dst_file = NULL;

static uint8_t *video_dst_data[4] = {NULL};
static int      video_dst_linesize[4];
static int video_dst_bufsize;

static int video_stream_idx = -1, audio_stream_idx = -1;
static AVFrame *frame = NULL;
static AVPacket pkt;

/* Enable or disable frame reference counting. You are not supposed to support
 * both paths in your application but pick the one most appropriate to your
 * needs. Look for the use of refcount in this example to see what are the
 * differences of API usage between them. */
static int refcount = 0;

#define MAX_STREAMS 16
struct stream_s
{
	struct ltntstools_throughput_s bitrate_tp;
	uint64_t pktCount;
	struct ltntstools_throughput_s time_tp;

	int64_t lastPTS;
	int64_t lastDTS;

	struct ltntstools_clock_s streamTimePTS;
	struct ltntstools_clock_s streamTimeDTS;
} g_streams[MAX_STREAMS];

static void streams_init()
{
	memset(&g_streams[0], 0, sizeof(g_streams));

	for (int i = 0; i < MAX_STREAMS; i++) {
		struct stream_s *strm = &g_streams[i];

		ltntstools_throughput_reset(&strm->bitrate_tp);
		ltntstools_throughput_reset(&strm->time_tp);

		ltntstools_clock_reset(&strm->streamTimePTS, 1000);
		ltntstools_clock_reset(&strm->streamTimeDTS, 1000);

	}
}

int64_t find_audio_to_video_drift_ms(int64_t *driftPTS, int64_t *driftDTS)
{
	struct stream_s *vstrm = &g_streams[video_stream_idx];
	struct stream_s *astrm = &g_streams[audio_stream_idx];

#if 0
	/* Get the PTS for each stream and calculate the tick offset from each other */
	int64_t v_ptsDrift = ltntstools_clock_get_drift_ms(&vstrm->streamTimePTS);
	int64_t a_ptsDrift = ltntstools_clock_get_drift_ms(&astrm->streamTimePTS);

	int64_t va_pts_drift = 0;
	if (v_ptsDrift < 0 && a_ptsDrift < 0)
		va_pts_drift = v_ptsDrift - a_ptsDrift;
	else
	if (v_ptsDrift >= 0 && a_ptsDrift >= 0)
		va_pts_drift = v_ptsDrift - a_ptsDrift;
	else
		va_pts_drift = v_ptsDrift + a_ptsDrift;
	
	/* Get the DTS for each stream and calculate the tick offset from each other */
	int64_t v_dtsDrift = ltntstools_clock_get_drift_ms(&vstrm->streamTimeDTS);
	int64_t a_dtsDrift = ltntstools_clock_get_drift_ms(&astrm->streamTimeDTS);

	int64_t va_dts_drift = 0;
	if (v_dtsDrift < 0 && a_dtsDrift < 0)
		va_dts_drift = v_dtsDrift - a_dtsDrift;
	else
	if (v_ptsDrift >= 0 && a_ptsDrift >= 0)
		va_dts_drift = v_dtsDrift - a_dtsDrift;
	else
		va_dts_drift = v_dtsDrift + a_dtsDrift;

	*driftPTS = va_pts_drift;
	*driftDTS = va_dts_drift;
#else
	*driftPTS = vstrm->lastPTS - astrm->lastPTS;
	*driftDTS = vstrm->lastDTS - astrm->lastDTS;
#endif
	return 0;
}

#if 0
static int analyze_frame(AVFrame *frm, int stream_idx)
{
	static int pager = 0;

	char frameType[3];
	if (frm->channels)
		sprintf(frameType, "A%02d", stream_idx);
	else
		sprintf(frameType, "V%02d", stream_idx);

	if (pager-- == 0) {
		pager = 24;
		printf("+Frame       Frame       Packet       Packet\n");
		printf("+ Type         pts          pts          dts\n");
		printf("+--------------------------------------------\n");
	}
	printf("   %3s%12" PRIi64 " %12" PRIi64 " %12" PRIi64 "\n",
		frameType,
		frm->pts,
		frm->pkt_pts,
		frm->pkt_dts);

	return 0;
}
#endif

static int analyze_packet(struct stream_s *strm, int cached, AVPacket *pkt)
{
	//printf("%s()\n", __func__);
	static int pager = 0;

	int64_t ptsDiff = pkt->pts - strm->lastPTS;
	int64_t dtsDiff = pkt->dts - strm->lastDTS;
	strm->lastPTS = pkt->pts;
	strm->lastDTS = pkt->dts;

	int64_t ptsDrift = ltntstools_clock_get_drift_ms(&strm->streamTimePTS);
	int64_t dtsDrift = ltntstools_clock_get_drift_ms(&strm->streamTimeDTS);

	char id[16];
	if (pkt->stream_index == video_stream_idx)
		sprintf(id, "V   %d", pkt->stream_index);
	else
		sprintf(id, "A   %d", pkt->stream_index);

	char ts[64];
	time_t now = time(NULL);
	sprintf(ts, "%s", ctime(&now));
	ts[ strlen(ts) - 1] = 0;

	if (pager-- == 0) {
		pager = 32;
		printf("+Strm - Packet -- @ %s"                    " ---------------------------->   Side <------------------------------------> <------------------   Wall/pts   Wall/dts <------------ <-------->\n", ts);
		printf("+  Id     Size           pts/interval           dts/interval      Duration  Items -- Data                                     Mb/ps  Content  drift(ms)  drift(ms)     aPTS-vPTS  aDTS-vDTS\n");
		printf("+---------------------------------------------------------------------(ms) <----> <------------------------------------> <--------------(ms)     < 0 = behind wall <--------(ms) <-----(ms)\n");
	}
	//printf("pkt.pts %" PRIi64 "\n", pkt->pts);
	
	printf("%3s %8d %13" PRIi64 " %8" PRIi64 " %13" PRIi64 " %8" PRIi64 " %13" PRIi64 "   %4d -- ",
		id,
		pkt->size,
		pkt->pts,
		ptsDiff,
		pkt->dts,
		dtsDiff,
		pkt->duration,
		pkt->side_data_elems);

	int len = pkt->size;
	if (len > 12)
		len = 12;
	for (int i = 0; i < len; i++)
		printf("%02x ", pkt->data[i]);
	for (int i = len; i < 12; i++)
		printf("   ")
;
	printf(" -- % 6.02f   %6d",
		ltntstools_throughput_get_mbps(&strm->bitrate_tp),
		ltntstools_throughput_get_value(&strm->time_tp));

	if (strm->pktCount > 200) {
		printf("  % 9" PRIi64 "  % 9" PRIi64,
			ptsDrift,
			dtsDrift);

		int64_t av_ptsDrift = 0, av_dtsDrift = 0;
		find_audio_to_video_drift_ms(&av_ptsDrift, &av_dtsDrift);

		printf("     % 9" PRIi64 "  % 9" PRIi64,
			av_ptsDrift, av_dtsDrift);
	}

	printf("\n");

	return 0;
}

static int decode_packet(struct stream_s *strm, int *got_frame, int cached)
{
    int ret = 0;
    int decoded = pkt.size;

    *got_frame = 0;

    ltntstools_throughput_write(&strm->bitrate_tp, pkt.data, pkt.size);
    ltntstools_throughput_write_value(&strm->time_tp, pkt.duration);

    if (pkt.stream_index == video_stream_idx) {
        /* decode video frame */
        ret = avcodec_decode_video2(video_dec_ctx, frame, got_frame, &pkt);
        if (ret < 0) {
            fprintf(stderr, "Error decoding video frame (%s)\n", av_err2str(ret));
            return ret;
        }

        if (*got_frame) {

            if (frame->width != width || frame->height != height ||
                frame->format != pix_fmt) {
                /* To handle this change, one could call av_image_alloc again and
                 * decode the following frames into another rawvideo file. */
                fprintf(stderr, "Error: Width, height and pixel format have to be "
                        "constant in a rawvideo file, but the width, height or "
                        "pixel format of the input video changed:\n"
                        "old: width = %d, height = %d, format = %s\n"
                        "new: width = %d, height = %d, format = %s\n",
                        width, height, av_get_pix_fmt_name(pix_fmt),
                        frame->width, frame->height,
                        av_get_pix_fmt_name(frame->format));
                return -1;
            }

#if 0
            printf("video_frame%s n:%d coded_n:%d\n",
                   cached ? "(cached)" : "",
                   video_frame_count++, frame->coded_picture_number);
#endif

            //analyze_frame(frame, pkt.stream_index);

            /* copy decoded frame to destination buffer:
             * this is required since rawvideo expects non aligned data */
            av_image_copy(video_dst_data, video_dst_linesize,
                          (const uint8_t **)(frame->data), frame->linesize,
                          pix_fmt, width, height);
#if 0
            /* write to rawvideo file */
            fwrite(video_dst_data[0], 1, video_dst_bufsize, video_dst_file);
#endif
        }
    } else if (pkt.stream_index == audio_stream_idx) {
        /* decode audio frame */
        ret = avcodec_decode_audio4(audio_dec_ctx, frame, got_frame, &pkt);
        if (ret < 0) {
            fprintf(stderr, "Error decoding audio frame (%s)\n", av_err2str(ret));
            return ret;
        }
        /* Some audio decoders decode only part of the packet, and have to be
         * called again with the remainder of the packet data.
         * Sample: fate-suite/lossless-audio/luckynight-partial.shn
         * Also, some decoders might over-read the packet. */
        decoded = FFMIN(ret, pkt.size);

        if (*got_frame) {
#if 0
            size_t unpadded_linesize = frame->nb_samples * av_get_bytes_per_sample(frame->format);
            printf("audio_frame%s n:%d nb_samples:%d pts:%s\n",
                   cached ? "(cached)" : "",
                   audio_frame_count++, frame->nb_samples,
                   av_ts2timestr(frame->pts, &audio_dec_ctx->time_base));
#endif

            //analyze_frame(frame, pkt.stream_index);
#if 0
            /* Write the raw audio data samples of the first plane. This works
             * fine for packed formats (e.g. AV_SAMPLE_FMT_S16). However,
             * most audio decoders output planar audio, which uses a separate
             * plane of audio samples for each channel (e.g. AV_SAMPLE_FMT_S16P).
             * In other words, this code will write only the first audio channel
             * in these cases.
             * You should use libswresample or libavfilter to convert the frame
             * to packed data. */
            fwrite(frame->extended_data[0], 1, unpadded_linesize, audio_dst_file);
#endif
        }
    }

    /* If we use frame reference counting, we own the data and need
     * to de-reference it when we don't use it anymore */
    if (*got_frame && refcount)
        av_frame_unref(frame);

    return decoded;
}

static int open_codec_context(int *stream_idx,
                              AVCodecContext **dec_ctx, AVFormatContext *fmt_ctx, enum AVMediaType type)
{
    int ret, stream_index;
    AVStream *st;
    AVCodec *dec = NULL;
    AVDictionary *opts = NULL;

    ret = av_find_best_stream(fmt_ctx, type, -1, -1, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "Could not find %s stream in input file '%s'\n",
                av_get_media_type_string(type), src_filename);
        return ret;
    } else {
        stream_index = ret;
        st = fmt_ctx->streams[stream_index];

        /* find decoder for the stream */
        dec = avcodec_find_decoder(st->codecpar->codec_id);
        if (!dec) {
            fprintf(stderr, "Failed to find %s codec\n",
                    av_get_media_type_string(type));
            return AVERROR(EINVAL);
        }

        /* Allocate a codec context for the decoder */
        *dec_ctx = avcodec_alloc_context3(dec);
        if (!*dec_ctx) {
            fprintf(stderr, "Failed to allocate the %s codec context\n",
                    av_get_media_type_string(type));
            return AVERROR(ENOMEM);
        }

        /* Copy codec parameters from input stream to output codec context */
        if ((ret = avcodec_parameters_to_context(*dec_ctx, st->codecpar)) < 0) {
            fprintf(stderr, "Failed to copy %s codec parameters to decoder context\n",
                    av_get_media_type_string(type));
            return ret;
        }

        /* Init the decoders, with or without reference counting */
        av_dict_set(&opts, "refcounted_frames", refcount ? "1" : "0", 0);
        if ((ret = avcodec_open2(*dec_ctx, dec, &opts)) < 0) {
            fprintf(stderr, "Failed to open %s codec\n",
                    av_get_media_type_string(type));
            return ret;
        }
        *stream_idx = stream_index;
    }

    return 0;
}

static int get_format_from_sample_fmt(const char **fmt,
                                      enum AVSampleFormat sample_fmt)
{
    int i;
    struct sample_fmt_entry {
        enum AVSampleFormat sample_fmt; const char *fmt_be, *fmt_le;
    } sample_fmt_entries[] = {
        { AV_SAMPLE_FMT_U8,  "u8",    "u8"    },
        { AV_SAMPLE_FMT_S16, "s16be", "s16le" },
        { AV_SAMPLE_FMT_S32, "s32be", "s32le" },
        { AV_SAMPLE_FMT_FLT, "f32be", "f32le" },
        { AV_SAMPLE_FMT_DBL, "f64be", "f64le" },
    };
    *fmt = NULL;

    for (i = 0; i < FF_ARRAY_ELEMS(sample_fmt_entries); i++) {
        struct sample_fmt_entry *entry = &sample_fmt_entries[i];
        if (sample_fmt == entry->sample_fmt) {
            *fmt = AV_NE(entry->fmt_be, entry->fmt_le);
            return 0;
        }
    }

    fprintf(stderr,
            "sample format %s is not supported as output format\n",
            av_get_sample_fmt_name(sample_fmt));
    return -1;
}

int rtmp_analyzer(int argc, char **argv)
{
#if 0
	struct ltntstools_clock_s c;
	ltntstools_clock_reset(&c, 1000);

	ltntstools_clock_establish_wallclock(&c, 40000);
	for (int i = 0; i < 50; i++)
		ltntstools_clock_add_ticks(&c, 40);

printf("%" PRIi64 " clkval\n", c.currentTime);
	sleep(1);
	printf("%" PRIi64 " drift(ms)\n", ltntstools_clock_get_drift_ms(&c));
	exit(0);
#endif
    int ret = 0, got_frame;
    avformat_network_init();
    streams_init();

    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s [-refcount] input_file video_output_file audio_output_file\n"
                "API example program to show how to read frames from an input file.\n"
                "This program reads frames from a file, decodes them, and writes decoded\n"
                "video frames to a rawvideo file named video_output_file, and decoded\n"
                "audio frames to a rawaudio file named audio_output_file.\n\n"
                "If the -refcount option is specified, the program use the\n"
                "reference counting frame system which allows keeping a copy of\n"
                "the data for longer than one decode call.\n"
                "\n", argv[0]);
        exit(1);
    }
    if (argc == 5 && !strcmp(argv[1], "-refcount")) {
        refcount = 1;
        argv++;
    }
    src_filename = argv[1];
    video_dst_filename = argv[2];
    audio_dst_filename = argv[3];

    /* register all formats and codecs */
    av_register_all();

    /* open input file, and allocate format context */
    if (avformat_open_input(&fmt_ctx, src_filename, NULL, NULL) < 0) {
        fprintf(stderr, "Could not open source file %s\n", src_filename);
        exit(1);
    }

    /* retrieve stream information */
    if (avformat_find_stream_info(fmt_ctx, NULL) < 0) {
        fprintf(stderr, "Could not find stream information\n");
        exit(1);
    }

    if (open_codec_context(&video_stream_idx, &video_dec_ctx, fmt_ctx, AVMEDIA_TYPE_VIDEO) >= 0) {
        video_stream = fmt_ctx->streams[video_stream_idx];

        video_dst_file = fopen(video_dst_filename, "wb");
        if (!video_dst_file) {
            fprintf(stderr, "Could not open destination file %s\n", video_dst_filename);
            ret = 1;
            goto end;
        }

        /* allocate image where the decoded image will be put */
        width = video_dec_ctx->width;
        height = video_dec_ctx->height;
        pix_fmt = video_dec_ctx->pix_fmt;
        ret = av_image_alloc(video_dst_data, video_dst_linesize,
                             width, height, pix_fmt, 1);
        if (ret < 0) {
            fprintf(stderr, "Could not allocate raw video buffer\n");
            goto end;
        }
        video_dst_bufsize = ret;
    }

    if (open_codec_context(&audio_stream_idx, &audio_dec_ctx, fmt_ctx, AVMEDIA_TYPE_AUDIO) >= 0) {
        audio_stream = fmt_ctx->streams[audio_stream_idx];
        audio_dst_file = fopen(audio_dst_filename, "wb");
        if (!audio_dst_file) {
            fprintf(stderr, "Could not open destination file %s\n", audio_dst_filename);
            ret = 1;
            goto end;
        }
    }

    /* dump input information to stderr */
    av_dump_format(fmt_ctx, 0, src_filename, 0);

    if (!audio_stream && !video_stream) {
        fprintf(stderr, "Could not find audio or video stream in the input, aborting\n");
        ret = 1;
        goto end;
    }

    frame = av_frame_alloc();
    if (!frame) {
        fprintf(stderr, "Could not allocate frame\n");
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* initialize packet, set data to NULL, let the demuxer fill it */
    av_init_packet(&pkt);
    pkt.data = NULL;
    pkt.size = 0;

    if (video_stream)
        printf("Demuxing video from file '%s' into '%s'\n", src_filename, video_dst_filename);
    if (audio_stream)
        printf("Demuxing audio from file '%s' into '%s'\n", src_filename, audio_dst_filename);

    /* read frames from the file */
    while (av_read_frame(fmt_ctx, &pkt) >= 0) {
        AVPacket orig_pkt = pkt;
        do {
            struct stream_s *strm = &g_streams[pkt.stream_index];

            /* Allow 200 packets for each stream before we establish wall time, this removes
             * the buffering that ffmpeg does and gives is something closer to actual walltime,
             * else the buffering skews time by about 1500ms.
             */
            if(strm->pktCount++ == 200) {
                ltntstools_clock_establish_wallclock(&strm->streamTimePTS, pkt.pts);
                ltntstools_clock_establish_wallclock(&strm->streamTimeDTS, pkt.dts);
            }
            ltntstools_clock_set_ticks(&strm->streamTimePTS, pkt.pts);
            ltntstools_clock_set_ticks(&strm->streamTimeDTS, pkt.dts);

            ret = analyze_packet(strm, 0, &pkt);
            ret = decode_packet(strm, &got_frame, 0);
            if (ret < 0)
                break;
            pkt.data += ret;
            pkt.size -= ret;
        } while (pkt.size > 0);
        av_packet_unref(&orig_pkt);
    }

    /* flush cached frames */
    struct stream_s *strm = &g_streams[pkt.stream_index];
    pkt.data = NULL;
    pkt.size = 0;
    do {
        decode_packet(strm, &got_frame, 1);
    } while (got_frame);

    printf("Demuxing succeeded.\n");

    if (video_stream) {
        printf("Play the output video file with the command:\n"
               "ffplay -f rawvideo -pix_fmt %s -video_size %dx%d %s\n",
               av_get_pix_fmt_name(pix_fmt), width, height,
               video_dst_filename);
    }

    if (audio_stream) {
        enum AVSampleFormat sfmt = audio_dec_ctx->sample_fmt;
        int n_channels = audio_dec_ctx->channels;
        const char *fmt;

        if (av_sample_fmt_is_planar(sfmt)) {
            const char *packed = av_get_sample_fmt_name(sfmt);
            printf("Warning: the sample format the decoder produced is planar "
                   "(%s). This example will output the first channel only.\n",
                   packed ? packed : "?");
            sfmt = av_get_packed_sample_fmt(sfmt);
            n_channels = 1;
        }

        if ((ret = get_format_from_sample_fmt(&fmt, sfmt)) < 0)
            goto end;

        printf("Play the output audio file with the command:\n"
               "ffplay -f %s -ac %d -ar %d %s\n",
               fmt, n_channels, audio_dec_ctx->sample_rate,
               audio_dst_filename);
    }

end:
    avcodec_free_context(&video_dec_ctx);
    avcodec_free_context(&audio_dec_ctx);
    avformat_close_input(&fmt_ctx);
    if (video_dst_file)
        fclose(video_dst_file);
    if (audio_dst_file)
        fclose(audio_dst_file);
    av_frame_free(&frame);
    av_free(video_dst_data[0]);

    return ret < 0;
}
