/* Copyright LiveTimeNet, Inc. 2021. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

#include <libltntstools/ltntstools.h>
#include "ffmpeg-includes.h"
#include "source-avio.h"
#include "golomb.h"
#include "codecs.h"
#include "testcase-428-dts.h"

#define LOCAL_DEBUG 0
#define H264_IFRAME_THUMBNAILING 0

static int testcase_428_dts_exists(uint32_t dts)
{
	for (unsigned int i = 0; i < (sizeof(testcase_428_dts) / sizeof(uint32_t)); i++) {
		if (testcase_428_dts[i] == dts) {
			return 1;
		} else
		if (testcase_428_dts[i] > dts) {
			return 0;
		}
	}

	return 0;
}
/* TODO: Move this into the libltntstools once we're completely happy with it.
 * See ISO-14496-10:2004 section 7.3.1 NAL unit Syntax.
 */
static void ltn_nal_h264_strip_emulation_prevention(struct ltn_nal_headers_s *h)
{
	int dropped = 0;
	for (unsigned int i = 1; i < h->lengthBytes; i++) {
		if (i + 2 < h->lengthBytes &&
			h->ptr[i + 0] == 0x00 &&
			h->ptr[i + 1] == 0x00 &&
			h->ptr[i + 2] == 0x03)
		{
				/* Convert 00 00 03 to 00 00 */
				memcpy((unsigned char *)&h->ptr[i + 2], &h->ptr[i + 3], h->lengthBytes - i - 3);
				dropped++;
		}
	}
	h->lengthBytes -= dropped;
}

#if H264_IFRAME_THUMBNAILING

/*
Disabled, pending relocation.

Code Here that produced full size stream snapshots for
a H264 stream. It belongs somewhere else.

The feature selectively decodes h264 streams and makes full sized
jpegs, every 5 seconds. The CPU burden is reduced by roughly 3-4x on
average (compared to a full process decode).

All of the ltntstools_h264_iframe_thumbnailer*() calls
belong in a deeper framework, once complete. They'ere here
today so we can quickly leverage the pes inspector to do some
heavy lifting for us.

Your may also be interested in, from ffmpeg, these files:
       get_bits.h
       golomb.h
       iframe.bin
       mathops.h
       put_bits.h
*/
#include "golomb.h"
static time_t g_nextThumbnailTime = 0;
#endif

#define DEFAULT_STREAMID 0xe0
#define DEFAULT_PID 0x31

static int g_running = 1;

struct nal_statistic_s
{
	int       enabled;       /* Boolean. */
	uint64_t  totalCount;    /* Number of messages received for this specific NAL */
	int64_t   bps;           /* Per NAL throughput bps */
	void     *throughputCtx; /* precise throughput framework handle */
};

struct nal_throughput_s
{
	time_t    lastReport;
	void     *throughputCtx; /* precise throughput framework handle */
	int64_t   bps;           /* Entire NAL stream bps */

// 31 Nals in H.264
// 63 Nals in H.265
#define MAX_NALS 63
	struct nal_statistic_s stats[MAX_NALS];
};

static void nal_throughput_init(struct nal_throughput_s *ctx)
{
	throughput_hires_alloc(&ctx->throughputCtx, 5000);

	for (int i = 0; i < MAX_NALS; i++) {
		throughput_hires_alloc(&ctx->stats[i].throughputCtx, 2000);
	}
}

static void nal_throughput_free(struct nal_throughput_s *ctx)
{
	throughput_hires_free(ctx->throughputCtx);

	for (int i = 0; i < MAX_NALS; i++) {
		throughput_hires_free(ctx->stats[i].throughputCtx);
	}
}

static void nal_throughput_report(struct nal_throughput_s *ctx, time_t now, int doH264NalThroughput, int doH265NalThroughput)
{
	printf("UnitType                                               Name   Mb/ps  Count @ %s",
		ctime(&now));

	int64_t summed_bps = 0;

	for (int i = 0; i < MAX_NALS; i++) {
		struct nal_statistic_s *nt = &ctx->stats[i]; 
		if (!nt->enabled)
			continue;

		summed_bps += nt->bps;

		const char *nalName = "";
		if (doH264NalThroughput) {
			nalName = h264Nals_lookupName(i);
		} else
		if (doH265NalThroughput) {
			nalName = h265Nals_lookupName(i);
		}
		printf("    0x%02x %50s %7.03f  %"PRIu64 "\n",
			i,
			nalName,
			(double)nt->bps / (double)1e6,
			nt->totalCount);

	}
	printf("--------                                                    %7.03f  Mb/ps\n", (double)summed_bps / (double)1e6);
}

#if H264_IFRAME_THUMBNAILING
/* Code that belongs in a core library, eventually once its working... */

/*
 * Purpose: Take a series of H264 NALS in, including SPS, PPS then an IFRAME,
 * decode the iframe into an in-memory jpg. Return the jpg to the caller.
 */
struct ltntstools_h264_iframe_thumbnailer_ctx_s
{
	void *userContext;
	int verbose;

	/* AVCodec Decoding to AVFrame */
	struct {
		const AVCodec *codec;
		AVCodecParserContext *parser;
		AVCodecContext *cc;
		AVFrame *frame;
		AVPacket *pkt;
	} dec, enc;

};

static int ltntstools_h264_iframe_thumbnailer_alloc_decoder(struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx)
{
	int t = AV_CODEC_ID_H264;
	ctx->dec.codec = avcodec_find_decoder(t);
	if (!ctx->dec.codec) {
        fprintf(stderr, "Could not find codec type 0x%x\n", t);
		return -1;
	}

	ctx->dec.parser = av_parser_init(ctx->dec.codec->id);
	if (!ctx->dec.parser) {
        fprintf(stderr, "Could not parser init\n");
		return -1;
	}

	ctx->dec.cc = avcodec_alloc_context3(ctx->dec.codec);
	if (!ctx->dec.cc) {
        fprintf(stderr, "Could not alloc cc\n");
		return -1;
	}

	/* open it */
    if (avcodec_open2(ctx->dec.cc, ctx->dec.codec, NULL) < 0) {
        fprintf(stderr, "Could not open codec\n");
        exit(1);
    }

	ctx->dec.frame = av_frame_alloc();
	if (!ctx->dec.frame) {
        fprintf(stderr, "Could not alloc frame\n");
		return -1;
	}

	ctx->dec.pkt = av_packet_alloc();
	if (!ctx->dec.pkt) {
        fprintf(stderr, "Could not alloc pkt\n");
		return -1;
	}

	return 0; /* Success */
}
static void ltntstools_h264_iframe_thumbnailer_free_decoder(struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx)
{
    av_parser_close(ctx->dec.parser);
    avcodec_free_context(&ctx->dec.cc);
    av_frame_free(&ctx->dec.frame);
    av_packet_free(&ctx->dec.pkt);
}

static int ltntstools_h264_iframe_thumbnailer_alloc_encoder(struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx, AVFrame *frm)
{
	int t = AV_CODEC_ID_MJPEG;
	ctx->enc.codec = avcodec_find_encoder(t);
	if (!ctx->enc.codec) {
        fprintf(stderr, "Could not find ecodec type 0x%x\n", t);
		return -1;
	}

	ctx->enc.parser = NULL;

	ctx->enc.cc = avcodec_alloc_context3(ctx->enc.codec);
	if (!ctx->enc.cc) {
        fprintf(stderr, "Could not alloc cc\n");
		return -1;
	}

	ctx->enc.cc->bit_rate = 400000;
	if (frm) {
		ctx->enc.cc->width = frm->width;
		ctx->enc.cc->height = frm->height;
	} else {
		ctx->enc.cc->width = 1920;
		ctx->enc.cc->height = 1080;
	}
	ctx->enc.cc->time_base = (AVRational){1, 25};
	ctx->enc.cc->framerate = (AVRational){1, 25};
	ctx->enc.cc->pix_fmt = AV_PIX_FMT_YUVJ420P;

	/* open it */
    if (avcodec_open2(ctx->enc.cc, ctx->enc.codec, NULL) < 0) {
        fprintf(stderr, "Could not open codec\n");
        exit(1);
    }

	ctx->enc.frame = NULL;

	ctx->enc.pkt = av_packet_alloc();
	if (!ctx->enc.pkt) {
        fprintf(stderr, "Could not alloc pkt\n");
		return -1;
	}

	return 0; /* Success */
}
static void ltntstools_h264_iframe_thumbnailer_free_encoder(struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx)
{
    avcodec_free_context(&ctx->enc.cc);
    av_packet_free(&ctx->enc.pkt);
}

int ltntstools_h264_iframe_thumbnailer_alloc(void **handle, void *userContext, int verbose)
{
	struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx = calloc(sizeof(*ctx), 1);
	if (!ctx) {
		return -1;
	}

	ctx->userContext = userContext;
	ctx->verbose = verbose;

	if (ltntstools_h264_iframe_thumbnailer_alloc_decoder(ctx) < 0) {
        fprintf(stderr, "Could not alloc decoder\n");
		return -1;
	}

	if (ltntstools_h264_iframe_thumbnailer_alloc_encoder(ctx, NULL) < 0) {
        fprintf(stderr, "Could not alloc encoder\n");
		return -1;
	}

	*handle = ctx;
	return 0; /* Success */
}

void ltntstools_h264_iframe_thumbnailer_free(void *handle)
{
	struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx = (struct ltntstools_h264_iframe_thumbnailer_ctx_s *)handle;
	if (!ctx)
		return;

	ltntstools_h264_iframe_thumbnailer_free_decoder(ctx);
	ltntstools_h264_iframe_thumbnailer_free_encoder(ctx);

	free(ctx);
}

static int ltntstools_h264_iframe_thumbnailer_avframe_scale_to_N(struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx, AVFrame *infrm, AVFrame **out, int out_w, int out_h)
{
	/* Scale any kind of YUV420P frame to 320x-1.
	 * Leave the inframe completely untouched.
	 * Return a new AVFrame as output.
	 */
	*out = NULL;

	int dst_w = out_w, dst_h = out_h;

	AVFrame *ofrm = av_frame_alloc();
	if (!ofrm) {
		fprintf(stderr, "%s() Failed allocating frame\n", __func__);
		return -1;
	}
	//avcodec_get_frame_defaults(ofrm);
	ofrm->width = dst_w;
	ofrm->height = dst_h;
	ofrm->format = infrm->format;

	int ret = av_image_alloc(&ofrm->data[0], &ofrm->linesize[0], ofrm->width, ofrm->height, ofrm->format, 1);
	if (ret < 0) {
		fprintf(stderr, "%s() Failed allocating image\n", __func__);
		av_frame_free(&frm);
		return -1;
	}

	struct SwsContext *sws_ctx = sws_getContext(
			infrm->width, infrm->height, infrm->format,
			dst_w, dst_h, infrm->format,
			SWS_BILINEAR, NULL, NULL, NULL);

	if (!sws_ctx) {
        fprintf(stderr,
			"Impossible to create scale context for the conversion "
			"fmt:%s s:%dx%d -> fmt:%s s:%dx%d\n",
			av_get_pix_fmt_name(infrm->format), infrm->width, infrm->height,
			av_get_pix_fmt_name(infrm->format), dst_w, dst_h);

		av_freep(&frm->data[0]);
		av_frame_free(&frm);
		sws_freeContext(sws_ctx);
		return -1;
	}

	/* convert to destination format */
	sws_scale(sws_ctx, (const uint8_t * const*)infrm->data, &infrm->linesize[0], 0, infrm->height, &ofrm->data[0], &ofrm->linesize[0]);

	sws_freeContext(sws_ctx);

	*out = ofrm;

	return 0; /* Success */
}

static int ltntstools_h264_iframe_thumbnailer_avframe_encode(struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx, AVFrame *frm, int quality)
{
	if (frm->width != ctx->enc.cc->width ||
		frm->height != ctx->enc.cc->height)
	{
		printf("Re-initializing the encoding codec\n");
		ltntstools_h264_iframe_thumbnailer_free_encoder(ctx);
		ltntstools_h264_iframe_thumbnailer_alloc_encoder(ctx, frm);
	}

	/* Drive the JPEG encoder quality */
	frm->quality = FF_LAMBDA_MAX * quality; /* Worst Quality is 31. best 1 */
	frm->pict_type = AV_PICTURE_TYPE_NONE;

	int ret = avcodec_send_frame(ctx->enc.cc, frm);
	if (ret < 0) {
		fprintf(stderr, "Error sending a frame for encoding\n");
		return -1;
	}

	while (ret >= 0) {
        ret = avcodec_receive_packet(ctx->enc.cc, ctx->dec.pkt);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
            return -1;
        else if (ret < 0) {
            fprintf(stderr, "Error during encoding\n");
            exit(1);
        }

		char fn[256];
		static int idx = 0;
		sprintf(fn, "%08d.jpg", idx++);

		time_t now = time(0);

		printf("Creating %s size %d @ %s", fn, ctx->dec.pkt->size, ctime(&now));
		FILE *fh = fopen(fn, "wb");
		if (fh) {
	        fwrite(ctx->dec.pkt->data, 1, ctx->dec.pkt->size, fh);
			fclose(fh);
		}

		g_nextThumbnailTime = time(0) + 5;

        av_packet_unref(ctx->dec.pkt);
    }

	return 0; /* Success */
}

static void ltntstools_h264_iframe_thumbnailer_avframe_dump(AVFrame *frm)
{
	printf("AVFrame %dx%d%c %s - linesize[0] = %d\n",
		frm->width, frm->height,
		frm->interlaced_frame ? 'i' : 'p',
		(char *)av_get_pix_fmt_name(frm->format),
		frm->linesize[0]);
}

static void ltntstools_h264_iframe_thumbnailer_decode(struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx, AVCodecContext *cc, AVFrame *frame, AVPacket *pkt, const char *filename)
{
    int ret = avcodec_send_packet(cc, pkt);
    if (ret < 0) {
        fprintf(stderr, "%s() Error sending a packet for decoding\n", __func__);
        return;
    }

    while (ret >= 0) {
        ret = avcodec_receive_frame(cc, frame);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            return;
		}
        else if (ret < 0) {
            fprintf(stderr, "%s() Error during decoding\n", __func__);
			return;
        }

		if (ctx->verbose)
		{
			ltntstools_h264_iframe_thumbnailer_avframe_dump(frame);
		}
		if (frame->key_frame) {
			AVFrame *frm;

			/* Encode the full frame using a quality scale of 1..31 where 1 is best */
			ltntstools_h264_iframe_thumbnailer_avframe_encode(ctx, frame, 10);
#if 1
			/* Created a 160x90 scaled version */
			ltntstools_h264_iframe_thumbnailer_avframe_scale_to_N(ctx, frame, &frm, 160, 90);

			/* Encode the scaled frame using a quality scale of 1..31 where 1 is best */
			ltntstools_h264_iframe_thumbnailer_avframe_encode(ctx, frm, 5);

			av_freep(&frm->data[0]);
			av_frame_free(&frm);
#endif
		}
    }
}

/* A caller may write a single complete nal, or multiple nals in a single buffer.
 * The nals must be complete,c annot be partial nals.
 * return 0 on success else < 0.
 */
int ltntstools_h264_iframe_thumbnailer_write(void *handle, const uint8_t *buf, int lengthBytes)
{
	struct ltntstools_h264_iframe_thumbnailer_ctx_s *ctx = (struct ltntstools_h264_iframe_thumbnailer_ctx_s *)handle;
	if (!ctx)
		return -1;

	int ret = av_parser_parse2(ctx->dec.parser, ctx->dec.cc,
		&ctx->dec.pkt->data, &ctx->dec.pkt->size,
		buf, lengthBytes,
		AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
	if (ret < 0) {
		fprintf(stderr, "Error while parsing\n");
		exit(1);
	}

	if (ctx->dec.pkt->size) {
		ltntstools_h264_iframe_thumbnailer_decode(ctx, ctx->dec.cc, ctx->dec.frame, ctx->dec.pkt, "thumbnail");
	}
	return 0; /* Success */
}

/* END: Code that belons in a core library, eventually once its working... */
#endif /* H264_IFRAME_THUMBNAILING */

struct tool_ctx_s
{
	int doH264NalThroughput;
	int doH265NalThroughput;
	int verbose;
	int doVBV;
	int pid;
	int testcase_validate;
	int streamId;
	void *pe;
	int writeES_h264;
	int writeES_h265;
	int writeES_payload;
	int writeThumbnails;
	uint64_t esSeqNr;
	int dumpPICTIMING;
	int analyzeAC3Headers;
	struct nal_throughput_s throughput;

#if H264_IFRAME_THUMBNAILING
	void *h264Thumbnailer;
#endif

	GetBitContext gb;

	struct ltn_pes_packet_writer_ctx writer_ctx;

	/* Video Buffer Verifier (VBV) */
	void *vbv;
	struct vbv_decoder_profile_s dp;

};

static void *vbv_notifications(void *userContext, enum ltntstools_vbv_event_e event)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;

	struct timeval now;
	gettimeofday(&now, NULL);

	printf("%d.%06d: pid 0x%04x (%04d) %s\n",
		(int)now.tv_sec, (int)now.tv_usec,
		ctx->pid, ctx->pid,
		ltntstools_vbv_event_name(event));

	return NULL;
}

static void _pes_packet_measure_nal_throughput(struct tool_ctx_s *ctx, struct ltn_pes_packet_s *pes, struct nal_throughput_s *s)
{
	struct nal_statistic_s *prevNal = NULL;

	throughput_hires_write_i64(ctx->throughput.throughputCtx, 0, pes->dataLengthBytes * 8, NULL);

    /* Pes payload may contain zero or more complete H264 nals. */ 
    int offset = -1, lastOffset = 0;
	unsigned int nalType = 0;
	int ret;
#if LOCAL_DEBUG		
	const char *nalName = NULL;
#endif
    while (1) {
		if (ctx->doH264NalThroughput) {
			ret = ltn_nal_h264_findHeader(pes->data, pes->dataLengthBytes, &offset);
		} else
		if (ctx->doH265NalThroughput) {
			ret = ltn_nal_h265_findHeader(pes->data, pes->dataLengthBytes, &offset);
		}
		if (ret < 0) {
			if (prevNal) {
				throughput_hires_write_i64(prevNal->throughputCtx, 0, (pes->dataLengthBytes - lastOffset) * 8, NULL);
			}
			break;
		}
		if (ctx->doH264NalThroughput) {
	  		nalType = pes->data[offset + 3] & 0x1f;
#if LOCAL_DEBUG		
			nalName = h264Nals_lookupName(nalType);
#endif
		} else
		if (ctx->doH265NalThroughput) {
			nalType = (pes->data[offset + 3] >> 1) & 0x3f;
#if LOCAL_DEBUG		
			nalName = h265Nals_lookupName(nalType);
#endif
		}

#if LOCAL_DEBUG		
        for (int i = 0; i < 5; i++) {
            printf("%02x ", *(pes->data + offset + i));
        }
        printf(": NalType %02x : %s\n", nalType, nalName);
#endif

		struct nal_statistic_s *nt = &ctx->throughput.stats[nalType];
		nt->enabled = 1;
		nt->totalCount++;

		if (!prevNal) {
			prevNal = nt;
			continue;
		}

		/* On a per NAL basis, maintain a throughput */
		throughput_hires_write_i64(prevNal->throughputCtx, 0, (offset - lastOffset) * 8, NULL);
	
		lastOffset = offset;
		prevNal = nt;
	}

	/* Summary report once per second */
	time_t now = time(NULL);
	if (now != ctx->throughput.lastReport) {
		ctx->throughput.lastReport = now;

		for (int i = 0; i < MAX_NALS; i++) {
			struct nal_statistic_s *nt = &ctx->throughput.stats[i];
			if (!nt->enabled)
				continue;

			nt->bps = throughput_hires_sumtotal_i64(nt->throughputCtx, 0, NULL, NULL);

			throughput_hires_expire(nt->throughputCtx, NULL);
		}

		ctx->throughput.bps = throughput_hires_sumtotal_i64(ctx->throughput.throughputCtx, 0, NULL, NULL);

		if (ctx->doH264NalThroughput || ctx->doH265NalThroughput) {
			nal_throughput_report(&ctx->throughput, now, ctx->doH264NalThroughput, ctx->doH265NalThroughput);
		}
		throughput_hires_expire(ctx->throughput.throughputCtx, NULL);
	}
}

static void _parse_PIC_TIMING(struct tool_ctx_s *ctx, struct ltn_nal_headers_s *e)
{
	/* Quick basic PIC timing parsing, we're assuming pic_struct_present is true,
	 * and CpbDpbDelaysPresentFlag is false, and we'll only look at the first clock in any stream.
	 * Tested against the LTN Encoder.
	 */

	/*
	 * 3 - SEI NAL (6)
	 * 4 - payloadType (1 = pic timing)
	 */      

/* Content dump of e->ptr
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
PIC_TIMING: 00 00 01 06 01 08 02 60 80 90 41 fd 12 7c 80 00 
PIC TIMING 15:18:52.31 disc:0 ct:0 counting_type:0 nuit:1 full_timestamp:1 cnt_dropped:0
PIC_TIMING: 00 00 01 06 01 08 02 80 20 90 41 dd 12 7c 80 00 
PIC_TIMING: 00 00 01 06 01 08 02 a0 20 90 41 ed 12 7c 80 00 
PIC_TIMING: 00 00 01 06 01 08 02 c0 80 90 42 2d 12 7c 80 00 
PIC TIMING 15:18:52.34 disc:0 ct:0 counting_type:0 nuit:1 full_timestamp:1 cnt_dropped:0
PIC_TIMING: 00 00 01 06 01 08 02 e0 20 90 42 0d 12 7c 80 00 
PIC_TIMING: 00 00 01 06 01 08 03 00 20 90 42 1d 12 7c 80 00 
PIC_TIMING: 00 00 01 06 01 08 03 20 80 90 42 5d 12 7c 80 00 
PIC TIMING 15:18:52.37 disc:0 ct:0 counting_type:0 nuit:1 full_timestamp:1 cnt_dropped:0
*/

#if LOCAL_DEBUG
	printf("PIC_TIMING: ");
	for (int z = 0; z < e->lengthBytes; z++) {
		printf("%02x ", e->ptr[z]);
	}
	printf("\n");
#endif

	init_get_bits8(&ctx->gb, &e->ptr[5], (e->lengthBytes - 5) * 8);

	int CpbDpbDelaysPresentFlag = 1; /* When NAL HRD present = 1 */
	int pic_struct_present_flag = 1;
	int clock_timestamp_flag[8];
	int cpb_removal_delay_length = 15; /* Video Engine - hardcoded */
	int dpb_removal_delay_length = 11; /* Video Engine - hardcoded */
	int time_offset_length = 0;

	if (ctx->pid == 0x31) {
		/* Hardcoded - LTN Encoder */
		cpb_removal_delay_length = 8;
		dpb_removal_delay_length = 0;
	}

	if (CpbDpbDelaysPresentFlag) {
		/* int cpb_removal_delay = */ get_bits_long(&ctx->gb, cpb_removal_delay_length);
		/* int dpb_removal_delay = */ get_bits_long(&ctx->gb, dpb_removal_delay_length);
#if LOCAL_DEBUG
		//printf("TIMING: cpb_removal_delay %d, dpb_removal_delay %d\n", cpb_removal_delay, dpb_removal_delay);
#endif
	}

	if (pic_struct_present_flag) {
		int clocks[16] = { 1, 1, 1, 2, 2, 3, 3, 2, 3, 0, 0, 0, 0, 0, 0 };

		int pic_struct = get_bits(&ctx->gb, 4);
#if LOCAL_DEBUG
		printf("TIMING: pic_struct %d (stream))\n", pic_struct);
#endif

		if (ctx->pid == 0x100) {
			pic_struct = 8; /* Hardcoded - Video Engine */
		}

//
//  PIC_TIMING: 00 00 01 06 01 09 3b 34 18 ef b0 00 00 03 00 20 80
//        PIC TIMING 00:59:59.24 struct:3 disc:0 ct:1 counting_type:6 nuit:1 full_timestamp:1 cnt_dropped:0
//  PIC_TIMING: 00 00 01 06 01 09 3b 34 00 00 03 00 80 00 00 20 80
//        PIC TIMING 06:00:00.00 struct:3 disc:0 ct:1 counting_type:6 nuit:1 full_timestamp:1 cnt_dropped:0
//
//    
//      PPPP C CC N           TTTT T F D F          NNNN|NNNN        SSSS|SSMM      MMMM|HHHH      H...|....      ....|.... 
//      0011 1 01 1    (3b)   0011 0 1 0 0    (34)  0000 0000   (00) 0000 0000 (00) 0000 0011 (03) 0000 0000 (00) 0000 1000 (08)     06:00:00.00
//      0011 1 01 1    (3b)   0011 0 1 0 0    (34)  0000 0000   (00) 0000 0000 (00) 0000 0000 (00) 0000 1000 (08)                    06:00:00.00
//

		int NumClocksTS = clocks[ pic_struct ];

#if LOCAL_DEBUG
		printf("TIMING: pic_struct %d NumClocksTS %d\n", pic_struct, NumClocksTS);
#endif

		for (int i = 0; i < NumClocksTS; i++) {
			clock_timestamp_flag[i] = get_bits(&ctx->gb, 1);
			if (clock_timestamp_flag[i]) {
				int ct_type               = get_bits(&ctx->gb, 2);
				int nuit_field_based_flag = get_bits(&ctx->gb, 1);
				int counting_type         = get_bits(&ctx->gb, 5);
				int full_timestamp_flag   = get_bits(&ctx->gb, 1);
				int discontinuity_flag    = get_bits(&ctx->gb, 1);
				int cnt_dropped_flag      = get_bits(&ctx->gb, 1);
				int n_frames              = get_bits(&ctx->gb, 8);

				if (full_timestamp_flag) {
					int seconds = get_bits(&ctx->gb, 6);
					int minutes = get_bits(&ctx->gb, 6);
					int hours   = get_bits(&ctx->gb, 5);

					printf("\tPIC TIMING %02d:%02d:%02d.%02d struct:%d disc:%d ct:%d counting_type:%d nuit:%d full_timestamp:%d cnt_dropped:%d\n",
						hours, minutes, seconds, n_frames,
						pic_struct,
						discontinuity_flag,
						ct_type, counting_type, nuit_field_based_flag,
						full_timestamp_flag,
						cnt_dropped_flag);

				} else {
					int seconds               = 0;
					int minutes               = 0;
					int hours                 = 0;
					int seconds_flag          = get_bits(&ctx->gb, 1);
					if (seconds_flag) {
						seconds               = get_bits(&ctx->gb, 6);
						int minutes_flag      = get_bits(&ctx->gb, 1);
						if (minutes_flag) {
							minutes           = get_bits(&ctx->gb, 6);
							int hours_flag    = get_bits(&ctx->gb, 1);
							if (hours_flag) {
								hours         = get_bits(&ctx->gb, 5);
							}
						}
					}
					printf("\tPIC TIMING %02d:%02d:%02d.%02d struct:%d disc:%d ct:%d counting_type:%d nuit:%d full_timestamp:%d cnt_dropped:%d\n",
						hours, minutes, seconds, n_frames,
						pic_struct,
						discontinuity_flag,
						ct_type, counting_type, nuit_field_based_flag,
						full_timestamp_flag,
						cnt_dropped_flag);
				}
				if (time_offset_length > 0) {
					/* int time_offset = */ get_bits_long(&ctx->gb, time_offset_length);
				}
			} /* if (clock_timestamp_flag[i]) */
		} /* for (int i = 0; i < NumClocksTS; i++) */
	} /* if (pic_struct_present_flag) */
}

static void _parse_AC3_Headers(struct tool_ctx_s *ctx, struct ltn_pes_packet_s *pes)
{
	printf("\nAC3: ");
	for (int i = 0; i < (8 + 14); i++) {
		printf("%02x ", pes->data[i]);
	}
	printf(" ...\n");

	struct ltn_ac3_header_syncframe_s frame;
	if (ltntstools_ac3_header_parse(&frame, pes->data, pes->dataLengthBytes) < 0) {
		fprintf(stderr, "Error decoding AC3 frame header, skipping\n");
		return;
	}

	ltntstools_ac3_header_dprintf(STDOUT_FILENO, &frame);
	printf("\n");

}

static void *callback(void *userContext, struct ltn_pes_packet_s *pes)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;
#if H264_IFRAME_THUMBNAILING
	GetBitContext gb;
	time_t now = time(0);
#endif

	if (ctx->verbose > 1) {
		printf("PES Extractor callback\n");
	}

	if (ctx->doVBV) {
		if (ltntstools_vbv_write(ctx->vbv, (const struct ltn_pes_packet_s *)pes) < 0) {
			fprintf(stderr, "Error writing PES to VBV\n");
		}
		ltn_pes_packet_free(pes);
		return NULL;
	}

	if (ctx->testcase_validate == 428) {
		if (pes->DTS && testcase_428_dts_exists(pes->DTS) == 0) {
			printf("DID NOT FIND DTS %" PRIi64  " in input stream!!!!!!!!!!\n", pes->DTS);
		}
	}
	if (ctx->writeES_payload) {
		ltn_pes_packet_save_es(&ctx->writer_ctx, pes);
		ltn_pes_packet_free(pes);
		return NULL;
	}

	/* Avoid segfaults if the user has elected for Headers Only */
	if (pes->dataLengthBytes == 0) {
		/* Else, dump all the PES packets */
		ltn_pes_packet_dump(pes, "");
		ltn_pes_packet_free(pes);
		return NULL;		
	}

	/* If we're analyzing NALs then ONLY do this.... */
	if (ctx->doH264NalThroughput || ctx->doH265NalThroughput) {
		_pes_packet_measure_nal_throughput(ctx, pes, &ctx->throughput);
	}

	if (ctx->analyzeAC3Headers) {
		if (ctx->verbose > 1) {
			ltn_pes_packet_dump_with_options(pes, "", 0x05);
		} else {
			ltn_pes_packet_dump_with_options(pes, "", 0x01);
		}
		/* Parse the first dozen or so bytes and dump to console */
		_parse_AC3_Headers(ctx, pes);
	} else {
		/* Else, dump all the PES packets */
		ltn_pes_packet_dump(pes, "");
	}

	if (ctx->writeES_h265) {
		int arrayLength = 0;
		struct ltn_nal_headers_s *array = NULL;
		if (ltn_nal_h265_find_headers(pes->data, pes->dataLengthBytes, &array, &arrayLength) == 0) {

			for (int i = 0; i < arrayLength; i++) {
				struct ltn_nal_headers_s *e = array + i;

				char fn[256];
				sprintf(&fn[0], "%014" PRIu64 "-es-pid-%04x-streamId-%02x-nal-%02x-name-%s.bin",
					ctx->esSeqNr++,
					ctx->pid,
					ctx->streamId,
					e->nalType,
					e->nalName);
				printf("Writing %s length %9d bytes\n", fn, e->lengthBytes);
				FILE *fh = fopen(fn, "wb");
				if (fh) {
					fwrite(e->ptr, 1, e->lengthBytes, fh);
					fclose(fh);
				}
			}
			free(array);

		} /* if find headers */

	}

	if (ctx->dumpPICTIMING) {
		int arrayLength = 0;
		struct ltn_nal_headers_s *array = NULL;
		if (ltn_nal_h264_find_headers(pes->data, pes->dataLengthBytes, &array, &arrayLength) == 0) {

			for (int i = 0; i < arrayLength; i++) {
				struct ltn_nal_headers_s *e = array + i;
				if (e->nalType == 0x6 /* SEI */ && e->ptr[4] == 0x01 /* SEI PAYLOAD_TYPE == PIC_TIMING */) {
					ltn_nal_h264_strip_emulation_prevention(e);
					_parse_PIC_TIMING(ctx, e);
				}
			} /* for (int i = 0; i < arrayLength; i++) */

			free(array);
		}
	}

	if (ctx->writeThumbnails || ctx->writeES_h264) {

		int arrayLength = 0;
		struct ltn_nal_headers_s *array = NULL;
		if (ltn_nal_h264_find_headers(pes->data, pes->dataLengthBytes, &array, &arrayLength) == 0) {

			for (int i = 0; i < arrayLength; i++) {
				struct ltn_nal_headers_s *e = array + i;

				if (ctx->writeES_h264) {
					char fn[256];
					sprintf(&fn[0], "%014" PRIu64 "-es-pid-%04x-streamId-%02x-nal-%02x-name-%s.bin",
						ctx->esSeqNr++,
						ctx->pid,
						ctx->streamId,
						e->nalType,
						e->nalName);
					printf("Writing %s length %9d bytes\n", fn, e->lengthBytes);
					FILE *fh = fopen(fn, "wb");
					if (fh) {
						fwrite(e->ptr, 1, e->lengthBytes, fh);
						fclose(fh);
					}
				}
			}

#if H264_IFRAME_THUMBNAILING
			if (ctx->writeThumbnails && (now >= g_nextThumbnailTime)) {

				/* Send the entire stream to the decoder until the
				 * first key_frame drops out of the decoder. At this we grab the first
				 * 'keyframe' and go back to a sleep for a while.
				 */
				for (int i = 0; i < arrayLength; i++) {
					struct ltn_nal_headers_s *e = array + i;

					switch(e->nalType) {
					case 1:
					case 2:
					case 5: /* slice_layer_without_partitioning_rbsp */
					case 19: /* slice_layer_without_partitioning_rbsp */
						init_get_bits8(&gb, e->ptr + 4, 4);
						get_ue_golomb(&gb); /* first_mb_in_slice */
						int slice_type = get_ue_golomb(&gb);

						//if ((slice_type == 2) || (slice_type == 4) || (slice_type == 7) || (slice_type == 9))
						{
							if (ltntstools_h264_iframe_thumbnailer_write(ctx->h264Thumbnailer, e->ptr, e->lengthBytes) < 0) {
								fprintf(stderr, "Unable to decode during write to thumbnailer\n");
							}
						}
						break;
					case 6: /* SEI */
					case 7: /* SPS */
					case 8: /* PPS */
					default:
						if (ltntstools_h264_iframe_thumbnailer_write(ctx->h264Thumbnailer, e->ptr, e->lengthBytes) < 0) {
							fprintf(stderr, "Unable to decode during write to thumbnailer\n");
						}
					}
				}

			}
			free(array);
#endif
		} /* if find headers */

	}

	ltn_pes_packet_free(pes);

	return NULL;
}

static void *_avio_raw_callback(void *userContext, const uint8_t *pkts, int packetCount)
{
	struct tool_ctx_s *ctx = (struct tool_ctx_s *)userContext;
	
	ltntstools_pes_extractor_write(ctx->pe, pkts, packetCount);

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
		g_running = 0;
		break;
	default:
		fprintf(stderr, "unsupported avio state %d\n", status);
	}
	return NULL;
}

static void usage(const char *progname)
{
	printf("\nA tool to extract and display PES packets from transport files or streams.\n");
	printf("Usage:\n");
	printf("  -i <url> Eg: rtp|udp://227.1.20.45:4001?localaddr=192.168.20.45\n"
               "           192.168.20.45 is the IP addr where we'll issue a IGMP join\n");
	printf("  -v Increase level of verbosity.\n");
	printf("  -h Display command line help.\n");
	printf("  -P 0xnnnn PID containing the program elementary stream [def: 0x%02x]\n", DEFAULT_PID);
	printf("  -S PES Stream Id. Eg. 0xe0 or 0xc0 [def: 0x%02x]\n", DEFAULT_STREAMID);
#if H264_IFRAME_THUMBNAILING
	printf("  -T Decode H264 I-Frames into local .jpg thumbnail files [def: no]\n");
#endif
	printf("  -A Extract AC3 headers and display fields [def: no]\n");
	printf("  -H Show PES headers only, don't parse payload. [def: disabled, payload shown]\n");
	printf("  -4 dump H.264 NAL headers (live stream only) and measure per-NAL throughput\n");
	printf("  -5 dump H.265 NAL headers (live stream only) and measure per-NAL throughput\n");
	printf("  -t dump H.264 PIC TIMING headers (experimental with PTS reordering) [def: disabled]\n");
	printf("  -V Run the Video Bitrate Verifier across this pid [def: no]\n");
	printf("  -G <dirname> write ES payload to individual sequences files [def: no]\n"
	       "     Eg. seq00000000000000-pts00000000000000-dts00000000000000-len00000000-crc00000000\n");
	printf("  -F write H.265 PES ES Nals to individual sequences files [def: no]\n");
	printf("  -E write H.264 PES ES Nals to individual sequences files [def: no]\n");
	printf("     Eg. 00000000046068-es-pid-0064-streamId-e0-nal-06-name-SEI.bin\n"
           "         00000000046067-es-pid-0064-streamId-e0-nal-06-name-SEI.bin\n"
           "         00000000046066-es-pid-0064-streamId-e0-nal-09-name-AUD.bin\n"
           "         00000000046072-es-pid-0064-streamId-e0-nal-08-name-PPS.bin\n"
           "         00000000046071-es-pid-0064-streamId-e0-nal-07-name-SPS.bin\n"
           "         00000000046070-es-pid-0064-streamId-e0-nal-09-name-AUD.bin\n"
           "         00000000046077-es-pid-0064-streamId-e0-nal-05-name-slice_layer_without_partitioning_rbsp IDR.bin\n");

}

int pes_inspector(int argc, char *argv[])
{
	struct tool_ctx_s myctx, *ctx;
	ctx = &myctx;
	memset(ctx, 0, sizeof(*ctx));

	ltn_pes_packet_writer_init(&ctx->writer_ctx, "./");

	nal_throughput_init(&ctx->throughput);

	ctx->streamId = DEFAULT_STREAMID;
	ctx->pid = DEFAULT_PID;

	int ch;
	char *iname = NULL;
	int headersOnly = 0;

	while ((ch = getopt(argc, argv, "@:45?AEFG:Hhvi:P:S:TtV")) != -1) {
		switch (ch) {
		case '@':
			ctx->testcase_validate = atoi(optarg);
			break;
		case '?':
		case 'h':
			usage(argv[0]);
			exit(1);
			break;
		case '4':
			ctx->doH264NalThroughput = 1;
			ctx->doH265NalThroughput = 0;
			break;
		case '5':
			ctx->doH264NalThroughput = 0;
			ctx->doH265NalThroughput = 1;
			break;
		case 'A':
			ctx->analyzeAC3Headers = 1;
			break;
		case 'E':
			ctx->writeES_h264 = 1;
			ctx->writeES_h265 = 0;
			break;
		case 'F':
			ctx->writeES_h264 = 0;
			ctx->writeES_h265 = 1;
			break;
		case 'G':
			ctx->writeES_payload = 1;
			ltn_pes_packet_writer_init(&ctx->writer_ctx, optarg);
			break;
		case 'H':
			headersOnly = 1;
			break;
		case 'i':
			iname = optarg;
			break;
		case 'P':
			if ((sscanf(optarg, "0x%x", &ctx->pid) != 1) || (ctx->pid > 0x1fff)) {
				if ((sscanf(optarg, "%d", &ctx->pid) != 1) || (ctx->pid > 0x1fff)) {
					usage(argv[0]);
					exit(1);
				}
			}
			break;
		case 'S':
			if ((sscanf(optarg, "0x%x", &ctx->streamId) != 1) || (ctx->streamId > 0xff)) {
				usage(argv[0]);
				exit(1);
			}
			break;
#if H264_IFRAME_THUMBNAILING
		case 'T':
			ctx->writeThumbnails = 1;
			break;
#endif
		case 't':
			ctx->dumpPICTIMING = 1;
			break;
		case 'v':
			ctx->verbose++;
			break;
		case 'V':
			ctx->doVBV = 1;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (ctx->pid == 0) {
		usage(argv[0]);
		fprintf(stderr, "\n-P is mandatory.\n\n");
		exit(1);
	}

	if (iname == NULL) {
		usage(argv[0]);
		fprintf(stderr, "\n-i is mandatory.\n\n");
		exit(1);
	}

#if H264_IFRAME_THUMBNAILING
	if (ctx->writeThumbnails) {
		if (ltntstools_h264_iframe_thumbnailer_alloc(&ctx->h264Thumbnailer, NULL, ctx->verbose) < 0) {
			fprintf(stderr, "\nUnable to allocate thumbnailer, aborting.\n\n");
			exit(1);
		}
	}
#endif

	if (ctx->doVBV) {
		if (ltntstools_vbv_profile_defaults(&ctx->dp, VBV_CODEC_H264, 32, 59.94) < 0) {
			fprintf(stderr, "Unable to allocate VBV size for profile, aborting.\n");
			exit(0);
		}
		if (ltntstools_vbv_profile_validate(&ctx->dp) == 0) {
			fprintf(stderr, "invalid decoder profile, aborting.\n");
			exit(0);
		}
		if (ltntstools_vbv_alloc(&ctx->vbv, ctx->pid, (vbv_callback)vbv_notifications, ctx, &ctx->dp) < 0) {
			fprintf(stderr, "invalid vbv context, aborting.\n");
			exit(0);
		}
	}

	if (ltntstools_pes_extractor_alloc(&ctx->pe, ctx->pid, ctx->streamId,
			(pes_extractor_callback)callback, ctx, (1024 * 1024), (2 * 1024 * 1024)) < 0) {
		fprintf(stderr, "\nUnable to allocate pes_extractor object.\n\n");
		exit(1);
	}
	
	ltntstools_pes_extractor_set_skip_data(ctx->pe, headersOnly);

	if (ctx->dumpPICTIMING) {
		/* We want the PIC decoding in the correct temporal order */
		ltntstools_pes_extractor_set_ordered_output(ctx->pe, 1);
	}

	if (1) {
		ltntstools_pes_extractor_set_pcr_pid(ctx->pe, 0x31);
	}

	struct ltntstools_source_avio_callbacks_s cbs = { 0 };
	cbs.raw = (ltntstools_source_avio_raw_callback)_avio_raw_callback;
	cbs.status = (ltntstools_source_avio_raw_callback_status)_avio_raw_callback_status;

	void *srcctx = NULL;
	int ret = ltntstools_source_avio_alloc(&srcctx, ctx, &cbs, iname);
	if (ret < 0) {
		fprintf(stderr, "-i syntax error\n");
		return 1;
	}

	while (g_running) {
		usleep(50 * 1000);
	}

	ltntstools_source_avio_free(srcctx);

	ltntstools_pes_extractor_free(ctx->pe);
	if (ctx->vbv) {
		ltntstools_vbv_free(ctx->vbv);
		ctx->vbv = NULL;
	}
	nal_throughput_free(&ctx->throughput);
#if H264_IFRAME_THUMBNAILING
	ltntstools_h264_iframe_thumbnailer_free(ctx->h264Thumbnailer);
#endif

	return 0;
}
