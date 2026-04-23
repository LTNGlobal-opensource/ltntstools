/* Copyright LiveTimeNet, Inc. 2026. All Rights Reserved. */

#include "splicer-types.h"

/* For a given pes, look at the vars and stream content.
 * determine of the pes begins with a MP2 sync marker.
 * Returns 1 on success else 0.
 */
int pes_contains_start_of_mp2_sync(const struct ltn_pes_packet_s *pes)
{
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* MP2 sync word 0xFFF */
	if (pes->data[0] != 0xff)
		return 0;
	/* C = MPEG Version == MP2*/
	if (pes->data[1] != 0xfc)
		return 0;

	return 1; /* MP1/L2 sync found */
}

/* For a given pes, look at the vars and stream content.
 * determine of the pes begins with a MP2 sync marker.
 * Returns 1 on success else 0.
 */
int pes_contains_start_of_ac3_sync(const struct ltn_pes_packet_s *pes)
{
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* Fixed sync 0x0B77 */
	if (pes->data[0] != 0x0B)
		return 0;
	if (pes->data[1] != 0x77)
		return 0;

	return 1; /* AC3 sync found */
}

int pes_contains_start_of_aac_sync(const struct ltn_pes_packet_s *pes)
{
	/* FFFn
	adts_fixed_header() {
    syncword                         12 bits  // 0xFFF
    ID                                1 bit   // 0=MPEG-4, 1=MPEG-2
    layer                             2 bits  // always 00
    protection_absent                 1 bit   // 1=no CRC

    profile                           2 bits  // 1 = AAC-LC
    sampling_frequency_index          4 bits
    private_bit                       1 bit
    channel_configuration             3 bits
    original_copy                     1 bit
    home                              1 bit
	}
	*/
	if (!ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)pes))
		return 0;

	if (pes->dataLengthBytes < 2)
		return 0;

	/* Fixed sync 0xFFF1 */
	if (pes->data[0] != 0xff)
		return 0;
	if (pes->data[1] != 0xf1)
		return 0;

	return 1; /* AAC ADTS sync found */
}

struct timing_item_s *timing_item_alloc(struct pes_item_s *item)
{
    if (!item)
        return NULL;

    if (!item->pes)
        return NULL;

	struct timing_item_s *ti = calloc(1, sizeof(*ti));
    if (ti) {
        ti->arrivalSTC    = item->arrivalSTC;
        ti->outputSTC     = item->outputSTC;
        ti->PTS_DTS_flags = item->pes->PTS_DTS_flags;
        ti->PTS           = item->pes->PTS;
        ti->DTS           = item->pes->DTS;
        ti->created       = time(NULL);
    }

	return ti;
}

void timing_item_free(struct timing_item_s *ti)
{
	free(ti);
}

void timing_item_dump(struct timing_item_s *ti)
{
    printf("ti %p, PTS_DTS_flags %d, PTS %" PRIi64 ", DTS %" PRIi64 "\n", ti, ti->PTS_DTS_flags, ti->PTS, ti->DTS);
}

static int timing_item_compute_pts_delta(struct timing_item_s *a, struct timing_item_s *b, int64_t *resultTicks)
{
    if (!a || !b) {
        return -1;
    }
    /* Ensure we have a PTS set on both timing contexts */
    if ((a->PTS_DTS_flags & 2) == 0 || (a->PTS_DTS_flags & 2) == 0) {
        return -2;
    }

    *resultTicks = a->PTS - b->PTS;

    return 0; /* Success */
}

static int timing_item_compute_dts_delta(struct timing_item_s *a, struct timing_item_s *b, int64_t *resultTicks)
{
    if (!a || !b) {
        return -1;
    }
    /* Ensure we have a PTS set on both timing contexts */
    if ((a->PTS_DTS_flags & 1) == 0 || (a->PTS_DTS_flags & 1) == 0) {
        return -2;
    }

    /* TODO: Deal with wrapping */
    *resultTicks = a->DTS - b->DTS;

    return 0; /* Success */
}

int timing_item_compute_delta(struct timing_item_s *a, struct timing_item_s *b, int64_t *resultTicks)
{
    int64_t ticks = 0;
    int ret = -1; /* Failed */

    if (timing_item_compute_dts_delta(a, b, &ticks) == 0) {
        /* Success, two frames each with a DTS, go with this value, typically VIDEO where a B frames is present */
        *resultTicks = ticks;
        ret = 0;
    } else
    if (timing_item_compute_pts_delta(a, b, &ticks) == 0) {
        /* Success, two frames each with a PTS, go with this value, typically AUDIO */
        *resultTicks = ticks;
        ret = 0;
    } else
    if (a->PTS_DTS_flags == 0 && b->PTS_DTS_flags == 0) {
        /* No timing on the contexts, therefore no tick difference. */
        *resultTicks = 0;
        ret = 0;
    } else {
        tprintf("BOOOOOOO, timing compute problem, aborting.\n");
        timing_item_dump(a);
        timing_item_dump(b);
    }

    return ret;
}

void pes_item_nals_dump(struct pes_item_s *item)
{
	for (int i = 0; i < item->nalArrayLength; i++) {
		struct ltn_nal_headers_s *nal = &item->nals[i];
		printf(" nal: %02x [%s]\n", nal->nalType, nal->nalName);
	}
}

void pes_item_nals_free(struct pes_item_s *item)
{
	if (item->nals) {
		free(item->nals);
		item->nals = NULL;
	}
	item->nalArrayLength = 0;
}

int pes_item_nals_alloc(struct pes_item_s *item)
{
	//struct tool_ctx_s *ctx = item->pid->stream->ctx;
	struct pid_s *pid = item->pid;

	unsigned int sliceType;

	/* Free any existing nals */
	pes_item_nals_free(item);

	/* Turn the PES into a series of NALS */
	if (ltn_nal_h264_find_headers(item->pes->data, item->pes->dataLengthBytes, &item->nals, &item->nalArrayLength) < 0) {
		return -1;
	}

	/* TODO: THIS IS AVC ONLY */
	for (int i = 0; i < item->nalArrayLength; i++) {
		struct ltn_nal_headers_s *nal = &item->nals[i];
		switch (nal->nalType) {
		case 1: /* slice_layer_without_partitioning_rbsp */
		case 2: /* slice_data_partition_a_layer_rbsp */
		case 5: /* Closed GOP - slice_layer_without_partitioning_rbsp */
		case 19: /* slice_layer_without_partitioning_rbsp */

            if (nal->nalType == 5) {
                item->video.has_avc_closed_gop = 1; /* Closed GOP - slice_layer_without_partitioning_rbsp */
                pid->count_frames_idr++;
            }

			if (h264_nal_get_slice_type_for_nal(nal, &sliceType) == 0) {
				//printf("SLICE TYPE %d, %s\n", sliceType, h264_slice_name_ascii(sliceType));
				if (h264_is_slice_type_iframe(sliceType)) {
					item->video.sliceType = SLICE_I;
					pid->count_frames_i++;
				} else
				if (h264_is_slice_type_bframe(sliceType)) {
					item->video.sliceType = SLICE_B;
					pid->count_frames_b++;
				} else
				if (h264_is_slice_type_pframe(sliceType)) {
					item->video.sliceType = SLICE_P;
					pid->count_frames_p++;
				}
			}
			break;
		case 7:
			item->video.has_avc_sps = 1;
			break;
		case 8:
			item->video.has_avc_pps = 1;
			break;
		case 9:
			item->video.has_avc_aud = 1;
			break;
        case 0xc: /* FILLER */
            item->video.has_avc_filler = 1;
            break;
        }
	}

	return 0; /* Success */
}

struct pes_item_s *pes_item_alloc(struct pid_s *pid, struct ltn_pes_packet_s *pes, struct output_stream_s *os)
{
    struct pes_item_s *item = calloc(1, sizeof(*item));
    if (!item) {
        return item;
    }

    item->pes = pes;
    item->pid = pid;
    item->created = time(NULL);
    item->arrivalSTC = output_get_computed_stc(os); /* We got the pes at the current STC */

    if (pid->type == PID_VIDEO) {
        item->outputSTC = output_get_computed_stc(os) + (27000 * 200); /* We'll schedule for output in 200ms */
    } else 
    if (pid->type == PID_AUDIO) {
        item->outputSTC = output_get_computed_stc(os) + (27000 * 200); /* We'll schedule for output in 200ms */
//        item->outputSTC = 0; // TODO: get_computed_stc(os);
    }

    if (ltn_pes_packet_is_video((struct ltn_pes_packet_s *)item->pes)) {
        //printf("pes contains video\n");
        item->type = PID_VIDEO;

        if (pes_item_nals_alloc(item) < 0) {
            fprintf(stderr, "asked to find nals, no nals found.... unusual, continuiting...\n");
        }
        /* item->video.has_XYZ are now set correctly */
#if 0
        if (pes->dataLengthBytes == 165) {
            ltn_pes_packet_dump(pes, "");
            pes_item_nals_dump(item);
            printf("made it to video\n");
            pes_item_dump(item, 1);
            //exit(1);
        }
#endif
    } else
    if (ltn_pes_packet_is_audio((struct ltn_pes_packet_s *)item->pes)) {
        item->type = PID_AUDIO;
        //printf("pes contains audio\n");
        if (pes_contains_start_of_mp2_sync(pes) == 1) {
            //printf("Contains MP1/L2 sync\n");
            item->audio.hasSync_MP1L2 = 1;
        } else
        if (pes_contains_start_of_ac3_sync(pes) == 1) {
            //printf("Contains AC3 sync\n");
            item->audio.hasSync_AC3 = 1;
        } else
        if (pes_contains_start_of_aac_sync(pes) == 1) {
            //printf("Contains AAC/ADTS sync\n");
            item->audio.hasSync_AAC = 1;
        }
    } else {
        item->type = PID_OTHER;
    }

    return item;
}

void pes_item_free(struct pes_item_s *item)
{
    if (item->pes) {
        ltn_pes_packet_free(item->pes);
        item->pes = NULL;
    }

    pes_item_nals_free(item);

    free(item);
}

void pes_item_dump(struct pes_item_s *item, int dumpNals)
{
    printf("item %p pes %p, pid %p", item, item->pes, item->pid);
    printf(", arrivalSTC %14" PRIi64 " outputSTC %14" PRIi64 " created %d type %d", item->arrivalSTC, item->outputSTC, (int)item->created, item->type);
    printf(", pes->dataLengthBytes %8d", item->pes->dataLengthBytes);
    if (item->type == PID_VIDEO) {
        printf(", item->video.sliceType %s (%d)",
            item->video.sliceType == SLICE_I ? "I" :
            item->video.sliceType == SLICE_B ? "B" :
            item->video.sliceType == SLICE_P ? "P" : "UNDEFINED",
            item->video.sliceType);

    }
    printf("\n");

    if (dumpNals) {
        pes_item_nals_dump(item);
    }
}


/*
 * ts_avpacket_dump.c
 *
 * Open an MPEG-TS file with FFmpeg and print packet timing/size info
 * for every AVPacket returned by av_read_frame().
 *
 * Build:
 *   cc -O2 -Wall -Wextra -o ts_avpacket_dump ts_avpacket_dump.c \
 *      $(pkg-config --cflags --libs libavformat libavcodec libavutil)
 *
 * Usage:
 *   ./ts_avpacket_dump input.ts
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
#include <libavutil/timestamp.h>

static const char *media_type_name(enum AVMediaType type)
{
    switch (type) {
    case AVMEDIA_TYPE_VIDEO:    return "video";
    case AVMEDIA_TYPE_AUDIO:    return "audio";
    case AVMEDIA_TYPE_SUBTITLE: return "subtitle";
    case AVMEDIA_TYPE_DATA:     return "data";
    default:                    return "other";
    }
}

int ffmpeg_demux_test(const char *ifn)
{
    AVFormatContext *fmt = NULL;
    AVPacket *pkt = NULL;
    int ret;

    /*
     * Force the MPEG-TS demuxer explicitly.
     * If you prefer autodetect, replace av_find_input_format("mpegts")
     * with NULL in avformat_open_input().
     */
    AVInputFormat *ifmt = av_find_input_format("mpegts");
    if (!ifmt) {
        fprintf(stderr, "Could not find FFmpeg mpegts demuxer\n");
        return 1;
    }

    if ((ret = avformat_open_input(&fmt, ifn, ifmt, NULL)) < 0) {
        fprintf(stderr, "avformat_open_input failed: %s\n", av_err2str(ret));
        return 1;
    }

    if ((ret = avformat_find_stream_info(fmt, NULL)) < 0) {
        fprintf(stderr, "avformat_find_stream_info failed: %s\n", av_err2str(ret));
        avformat_close_input(&fmt);
        return 1;
    }

    printf("Input: %s\n", ifn);
    printf("Demuxer: %s\n", fmt->iformat ? fmt->iformat->name : "unknown");
    printf("Streams: %u\n\n", fmt->nb_streams);

    for (unsigned i = 0; i < fmt->nb_streams; i++) {
        AVStream *st = fmt->streams[i];
        AVCodecParameters *par = st->codecpar;

        int pid = -1;
        AVDictionaryEntry *m = av_dict_get(st->metadata, "id", NULL, 0);
        if (m)
            pid = (int)strtol(m->value, NULL, 0);

        printf("Stream %u: type=%6s codec_id=%6d time_base=%d/%d",
               i,
               media_type_name(par->codec_type),
               par->codec_id,
               st->time_base.num,
               st->time_base.den);

        if (st->id >= 0)
            printf(" stream_id=0x%x", st->id);

        if (pid >= 0)
            printf(" metadata_id=%d", pid);

        printf("\n");
    }

    printf("\nPackets:\n");

    pkt = av_packet_alloc();
    if (!pkt) {
        fprintf(stderr, "av_packet_alloc failed\n");
        avformat_close_input(&fmt);
        return 1;
    }

    while ((ret = av_read_frame(fmt, pkt)) >= 0) {
        AVStream *st = fmt->streams[pkt->stream_index];

        /*
         * In MPEG-TS, st->id is commonly the PID when available.
         * This is usually what you want to print.
         */
        int pid = st->id;

        char pts_buf[AV_TS_MAX_STRING_SIZE];
        char dts_buf[AV_TS_MAX_STRING_SIZE];
        char dur_buf[AV_TS_MAX_STRING_SIZE];
        char pts_time_buf[AV_TS_MAX_STRING_SIZE];
        char dts_time_buf[AV_TS_MAX_STRING_SIZE];
        char dur_time_buf[AV_TS_MAX_STRING_SIZE];

        av_ts_make_string(pts_buf, pkt->pts);
        av_ts_make_string(dts_buf, pkt->dts);
        av_ts_make_string(dur_buf, pkt->duration);

        av_ts_make_time_string(pts_time_buf, pkt->pts, &st->time_base);
        av_ts_make_time_string(dts_time_buf, pkt->dts, &st->time_base);
        av_ts_make_time_string(dur_time_buf, pkt->duration, &st->time_base);


        if (pid == 0x131 || pid == 0x31) {
            printf("stream=%2d pid=0x%04x type=%s "
                "pts=%14s (%12ss) dts=%s (%12ss) dur=%5s (%12ss) "
                "size=%8d flags=%c%c\n",
                pkt->stream_index,
                pid >= 0 ? pid : 0,
                media_type_name(st->codecpar->codec_type),
                pts_buf, pts_time_buf,
                dts_buf, dts_time_buf,
                dur_buf, dur_time_buf,
                pkt->size,
                (pkt->flags & AV_PKT_FLAG_KEY) ? 'K' : '-',
                (pkt->flags & AV_PKT_FLAG_CORRUPT) ? 'C' : '-');

            if (pkt->size == 165) {
                ltntstools_hexdump(pkt->data, pkt->size, 32);
            }

            av_packet_unref(pkt);
        }
    }

    if (ret != AVERROR_EOF) {
        fprintf(stderr, "av_read_frame failed: %s\n", av_err2str(ret));
    }

    av_packet_free(&pkt);
    avformat_close_input(&fmt);
    return 0;
}