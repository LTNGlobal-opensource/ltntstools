#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libltntstools/ltntstools.h>
#include <libavutil/internal.h>
#include <libavcodec/golomb.h>
#include "codecs.h"

#define LOCAL_DEBUG 0

struct h264_codec_metadata_ctx_s
{
    uint16_t pid;
    uint8_t  streamId;

    /* PES extraction */
    void *pes;

    /* NAL Parsing */
    GetBitContext gb;
    int parseComplete;

    /* user facing results */
    struct h264_codec_metadata_results_s results;

    time_t lastComplete;

};

static int h264_parse_slice_layer_without_partitioning_rbsp(struct h264_codec_metadata_ctx_s *ctx)
{
    struct h264_codec_metadata_results_s *r = &ctx->results;
    struct h264_slice_s *s = &r->slice;

    s->first_mb_in_slice = get_ue_golomb(&ctx->gb); /* first_mb_in_slice */
	s->slice_type = get_ue_golomb(&ctx->gb);

    return 0; /* Success */
}

/* ISO14496-10 - 7.3.2.4 */
static int h264_parse_aud(struct h264_codec_metadata_ctx_s *ctx)
{
    struct h264_codec_metadata_results_s *r = &ctx->results;
    struct h264_aud_s *aud = &r->aud;
#if LOCAL_DEBUG
    printf("%s() begin\n", __func__);
#endif

    aud->primary_pic_type = get_bits(&ctx->gb, 3);

#if LOCAL_DEBUG
    printf("aud.primary_pic_type = %s (%02x)\n",
            aud->primary_pic_type == 0 ? "I" :
            aud->primary_pic_type == 1 ? "I,P" :
            aud->primary_pic_type == 2 ? "I,P,B" :
            aud->primary_pic_type == 3 ? "SI" :
            aud->primary_pic_type == 4 ? "SI,SP" :
            aud->primary_pic_type == 5 ? "I,SI" :
            aud->primary_pic_type == 6 ? "I,SI,P,SP" :
            aud->primary_pic_type == 7 ? "I,SI,P,SP,B" :
            "Illegal value",
            aud->primary_pic_type
    );
#endif

#if LOCAL_DEBUG
    printf("%s() end\n", __func__);
#endif
    return 0; /* Success */
}

/* ISO14496-10 - 7.3.2.1.1 */

static char *h264_profile_idc_lookup(uint32_t idc)
{
    switch (idc) {
    case  66: return "Baseline";
    case  77: return "Main";
    case  88: return "Extended";
    case 100: return "High";
    default: return "Unknown";
    }
}

static char *h264_chroma_format_idc_lookup(uint32_t idc)
{
    switch (idc) {
    case 0: return "Monochrome";
    case 1: return "4:2:0";
    case 2: return "4:2:2";
    case 3: return "4:4:4";
    default: return "Unknown";
    }
}

static void scaling_list(struct h264_codec_metadata_ctx_s *ctx, uint32_t *scaling_list, int sizeOfScalingList, uint32_t *useDefaultScalingMatrixFlag)
{
    //struct h264_codec_metadata_results_s *r = &ctx->results;
    //struct h264_seq_parameter_set_rbsp_s *sps = &r->sps;

    int lastScale = 8;
    int nextScale = 8;

    for (int j = 0; j < sizeOfScalingList; j++) {
        if (nextScale != 0) {
            int delta_scale =  get_se_golomb(&ctx->gb);
            nextScale = (lastScale + delta_scale + 256) % 256;
            *useDefaultScalingMatrixFlag = (j == 0 && nextScale == 0);
        }
        *(scaling_list + j) = (nextScale == 0) ? lastScale : nextScale;
        lastScale = *(scaling_list + j);
    }
}

static int h264_parse_sps(struct h264_codec_metadata_ctx_s *ctx)
{
    struct h264_codec_metadata_results_s *r = &ctx->results;
    struct h264_seq_parameter_set_rbsp_s *sps = &r->sps;
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    sps->profile_idc = get_bits(&ctx->gb, 8);
    get_bits(&ctx->gb, 6); /* Discard 6 constraint bits */
    get_bits(&ctx->gb, 2); /* Reserved */
    sps->level_idc = get_bits(&ctx->gb, 8);

    get_ue_golomb_31(&ctx->gb); /* seq_parameter_set_id */

    if (sps->profile_idc == 100 ||  // High profile
        sps->profile_idc == 110 ||  // High10 profile
        sps->profile_idc == 122 ||  // High422 profile
        sps->profile_idc == 244 ||  // High444 Predictive profile
        sps->profile_idc ==  44 ||  // Cavlc444 profile
        sps->profile_idc ==  83 ||  // Scalable Constrained High profile (SVC)
        sps->profile_idc ==  86 ||  // Scalable High Intra profile (SVC)
        sps->profile_idc == 118 ||  // Stereo High profile (MVC)
        sps->profile_idc == 128 ||  // Multiview High profile (MVC)
        sps->profile_idc == 138 ||  // Multiview Depth High profile (MVCD)
        sps->profile_idc == 139 ||  // ?
        sps->profile_idc == 134)
    {  // ?

        sps->chroma_format_idc = get_ue_golomb_31(&ctx->gb);
        if (sps->chroma_format_idc == 3) {
            sps->separate_colour_plane_flag = get_bits(&ctx->gb, 1);
        }
        sps->bit_depth_luma_minus8 = get_ue_golomb(&ctx->gb);
        sps->bit_depth_chroma_minus8 = get_ue_golomb(&ctx->gb);

        sps->qpprime_y_zero_transform_bypass_flag = get_bits(&ctx->gb, 1);

        sps->seq_scaling_matrix_present_flag = get_bits(&ctx->gb, 1);
        if (sps->seq_scaling_matrix_present_flag) {

            for (int i = 0; i < ((sps->chroma_format_idc != 3) ? 8 : 12); i++) {

                sps->seq_scaling_matrix_present_array[i].seq_scaling_matrix_present_flag = get_bits(&ctx->gb, 1);

                if (sps->seq_scaling_matrix_present_array[i].seq_scaling_matrix_present_flag) {

                    uint32_t useDefaultScalingMatrixFlag[12];
                    if (i < 6) {
                        scaling_list(ctx, &sps->seq_scaling_matrix_present_array[i].scaling_list_4x4[0], 16, &useDefaultScalingMatrixFlag[i]);
                    } else {
                        scaling_list(ctx, &sps->seq_scaling_matrix_present_array[i].scaling_list_8x8[0], 64, &useDefaultScalingMatrixFlag[i - 6]);
                    }
                }
            }
        }
    } else {
        /* It's undefined outside of the above profiles, and is thus 4:2:0 */
        sps->chroma_format_idc = 1; /* 4:2:0 */
    }

    sps->log2_max_frame_num_minus4 = get_ue_golomb(&ctx->gb);
    sps->pict_order_cnt_type = get_ue_golomb(&ctx->gb);

    if (sps->pict_order_cnt_type == 0) {
        sps->log2_max_pic_order_cnt_lab_minus4 = get_ue_golomb(&ctx->gb);
    } else if (sps->pict_order_cnt_type == 1) {
        sps->delta_pic_order_always_zero_flag = get_bits(&ctx->gb, 1);
        sps->offset_for_non_ref_pic = get_se_golomb(&ctx->gb);
        sps->offset_for_top_to_bottom_field = get_se_golomb(&ctx->gb);
        int num_ref_frames_in_pic_order_cnt_cycle = get_ue_golomb(&ctx->gb);
        for (int i = 0; i < num_ref_frames_in_pic_order_cnt_cycle; i++) {
                get_se_golomb(&ctx->gb);
        }
    }
    sps->num_ref_frames = get_ue_golomb_31(&ctx->gb);
    sps->gaps_in_frame_num_value_allowed_flag = get_bits(&ctx->gb, 1);
    sps->pic_width_in_mbs_minus1 = get_ue_golomb(&ctx->gb);
    sps->pic_height_in_map_minus1 = get_ue_golomb(&ctx->gb);
    sps->pic_width = (sps->pic_width_in_mbs_minus1 + 1) * 16;
    sps->pic_height = (sps->pic_height_in_map_minus1 + 1) * 16;

    sps->frame_mbs_only_flag = get_bits(&ctx->gb, 1);
    sps->mb_adaptive_frame_field_flag = 0;
    if (!sps->frame_mbs_only_flag) {
        sps->mb_adaptive_frame_field_flag = get_bits(&ctx->gb, 1);
    }

    sps->direct_8x8_inference_flag = get_bits(&ctx->gb, 1);
    sps->frame_cropping_flag = get_bits(&ctx->gb, 1);
    if (sps->frame_cropping_flag) {
        sps->frame_cropping_left_offset = get_ue_golomb(&ctx->gb);
        sps->frame_cropping_right_offset = get_ue_golomb(&ctx->gb);
        sps->frame_cropping_top_offset = get_ue_golomb(&ctx->gb);
        sps->frame_cropping_bottom_offset = get_ue_golomb(&ctx->gb);
    }

    sps->vui_parameters_present_flag = get_bits(&ctx->gb, 1);
    if (sps->vui_parameters_present_flag) {
        sps->aspect_ratio_info_present_flag = get_bits(&ctx->gb, 1);
        if (sps->aspect_ratio_info_present_flag) {
                sps->aspect_ratio_idc = get_bits(&ctx->gb, 8);
                if (sps->aspect_ratio_idc == 0) {
                        sps->sar_width = get_bits(&ctx->gb, 16);
                        sps->sar_height = get_bits(&ctx->gb, 16);
                }
        }

        sps->overscan_info_present_flag = get_bits(&ctx->gb, 1);
        if (sps->overscan_info_present_flag)
                sps->overscan_appropriate_flag = get_bits(&ctx->gb, 1);

        sps->video_signal_type_present_flag = get_bits(&ctx->gb, 1);
        if (sps->video_signal_type_present_flag) {
                sps->video_format = get_bits(&ctx->gb, 3);
                sps->video_full_range_flag = get_bits(&ctx->gb, 1);
                sps->colour_description_present_flag = get_bits(&ctx->gb, 1);
                if (sps->colour_description_present_flag) {
                        sps->colour_primaries = get_bits(&ctx->gb, 8);
                        sps->transfer_characteristics = get_bits(&ctx->gb, 8);
                        sps->matrix_coefficients = get_bits(&ctx->gb, 8);
                }
        }

        sps->chroma_loc_info_present_flag = get_bits(&ctx->gb, 1);
        if (sps->chroma_loc_info_present_flag) {
                sps->chroma_sample_loc_type_top_field = get_ue_golomb(&ctx->gb);
                sps->chroma_sample_loc_type_bottom_field = get_ue_golomb(&ctx->gb);
        }

        sps->timing_info_present_flag = get_bits(&ctx->gb, 1);
        if (sps->timing_info_present_flag) {
                /* This doesn't match the 2004 spec, but it does match the intel and elecard parsing. */
                /* Note that we can't read 32bit via the ffmpeg macro, so we're reading 2 * 16. */
                sps->num_units_in_tick  = get_bits(&ctx->gb, 16) << 16;
                sps->num_units_in_tick |= get_bits(&ctx->gb, 16);

                sps->time_scale  = get_bits(&ctx->gb, 16) << 16;
                sps->time_scale |= get_bits(&ctx->gb, 16);
                sps->fixed_frame_rate_flag = get_bits(&ctx->gb, 1);

                /* StreamEye Studio shows time_scale as 120000 but interprets it as div by 2 */
                if (sps->time_scale == 120000)
                    sps->time_scale /= 2;
        }

        sps->nal_hrd_parameters_present_flag = get_bits(&ctx->gb, 1);
        if (sps->nal_hrd_parameters_present_flag) {
                //printf("todo sps->nal_hrd_parameters_present_flag\n");
                goto out1;
        }

        sps->vcl_hrd_parameters_present_flag = get_bits(&ctx->gb, 1);
        if (sps->vcl_hrd_parameters_present_flag) {
                //printf("todo sps->vcl_hrd_parameters_present_flag\n");
                goto out1;
        }

        sps->pic_struct_present_flag = get_bits(&ctx->gb, 1);

        sps->bitstream_restriction_flag = get_bits(&ctx->gb, 1);
        if (sps->bitstream_restriction_flag) {
                sps->motion_vectors_over_pic_boundaries_flag = get_bits(&ctx->gb, 1);
                sps->max_bytes_per_pic_denom = get_ue_golomb(&ctx->gb);
                sps->max_bits_per_mb_denom = get_ue_golomb(&ctx->gb);
                sps->log2_max_mv_length_vertical = get_ue_golomb(&ctx->gb);
                sps->log2_max_mv_length_horizontal = get_ue_golomb(&ctx->gb);
                sps->num_reorder_frames = get_ue_golomb(&ctx->gb);
                sps->max_dec_frame_buffering = get_ue_golomb(&ctx->gb);
        }
    }

out1:

// ----
    strcpy(&sps->profile_idc_ascii[0], h264_profile_idc_lookup(sps->profile_idc));
    strcpy(&sps->chroma_format_idc_ascii[0], h264_chroma_format_idc_lookup(sps->chroma_format_idc));
    sprintf(&sps->level_idc_ascii[0], "%.1f", (double)sps->level_idc / 10);

    sprintf(&sps->bit_depth_luma_ascii[0], "%dbit", sps->bit_depth_luma_minus8 + 8);

    if (sps->timing_info_present_flag) {
        sprintf(&sps->timing_info_fps_ascii[0], "%.2ffps %s", (double)sps->time_scale / (double)sps->num_units_in_tick,
            sps->fixed_frame_rate_flag ? "fixed" : "variable");
    } else {
        sps->timing_info_fps_ascii[0] = 0;
    }

    sprintf(&sps->video_colorspace_ascii[0], "%s profile %s, %s, %s",
        sps->profile_idc_ascii,
        sps->level_idc_ascii,
        sps->chroma_format_idc_ascii,
        sps->bit_depth_luma_ascii);

    sprintf(&sps->video_format_ascii[0], "%dx%d %s",
        sps->pic_width, sps->pic_height,
        sps->timing_info_fps_ascii);


#if LOCAL_DEBUG
    printf("sps.video_format      = %s\n", sps->video_format_ascii);
    printf("sps.profile_idc       = %d [%s]\n", sps->profile_idc, sps->profile_idc_ascii);
    printf("sps.level_idc         = %d [%s]\n", sps->level_idc, sps->level_idc_ascii);
    printf("sps.chroma_format_idc = %d [%s]\n", sps->chroma_format_idc, sps->chroma_format_idc_ascii);

    printf("sps.pic_width         = %d\n", sps->pic_width);
    printf("sps.pic_height        = %d\n", sps->pic_height);
    printf("sps.bit_depth_chroma  = %d\n", sps->bit_depth_chroma_minus8 + 8);
    printf("sps.bit_depth_luma    = %d [%s]\n", sps->bit_depth_luma_minus8 + 8, sps->bit_depth_luma_ascii);
    printf("sps.vui_parameters_present_flag = %d\n", sps->vui_parameters_present_flag);
    printf("aspect_ratio_info_present_flag       = %d\n", sps->aspect_ratio_info_present_flag);
    printf("overscan_info_present_flag           = %d\n", sps->overscan_appropriate_flag);
    printf("video_signal_type_present_flag       = %d\n", sps->video_signal_type_present_flag);
    printf("chroma_loc_info_present_flag         = %d\n", sps->chroma_loc_info_present_flag);
    printf("timing_info_present_flag             = %d\n", sps->timing_info_present_flag);
    if (sps->timing_info_present_flag) {
        printf(" num_units_in_tick                   = %d\n", sps->num_units_in_tick);
        printf(" time_scale                          = %d\n", sps->time_scale);
        printf(" fixed_frame_rate_flag               = %d\n", sps->fixed_frame_rate_flag);
    }

    printf("nal_hrd_parameters_present_flag      = %d\n", sps->nal_hrd_parameters_present_flag);
    printf("vcl_hrd_parameters_present_flag      = %d\n", sps->nal_hrd_parameters_present_flag);
    printf("pic_struct_present_flag              = %d\n", sps->pic_struct_present_flag);
    printf("bitstream_restriction_flag           = %d\n", sps->bitstream_restriction_flag);

#endif

    ctx->parseComplete = 1;

    return 0; /* Success */
}

static void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
    struct h264_codec_metadata_ctx_s *ctx = (struct h264_codec_metadata_ctx_s *)userContext;

#if LOCAL_DEBUG
    printf("%s() begins\n", __func__);
#endif

    /* Pes payload may contain zero or more complete H264 nals. */ 
    int offset = -1;
    while (1) {
        int ret = ltn_nal_h264_findHeader(pes->data, pes->dataLengthBytes, &offset);
        if (ret < 0) {
            break;
        }

  		unsigned int nalType = pes->data[offset + 3] & 0x1f;

#if LOCAL_DEBUG
		const char *nalName = h264Nals_lookupName(nalType);

        for (int i = 0; i < 5; i++) {
            printf("%02x ", *(pes->data + offset + i));
        }
        printf(": NalType %02x : %s\n", nalType, nalName);
#endif
        
        init_get_bits8(&ctx->gb, pes->data + offset + 4, pes->dataLengthBytes - (offset + 4));
        switch (nalType) {
        case 0x02:
#if 0
/* No slice headers in
slice_data_partition_a_layer_rbsp( )
slice_data_partition_b_layer_rbsp( )
 */
        case 0x03:
        case 0x04:
#endif
        case 0x01:
        case 0x05:
            ret = h264_parse_slice_layer_without_partitioning_rbsp(ctx);
            //printf("slice_type %d (%s)\n", ctx->results.slice.slice_type, h274_slice_name_ascii(ctx->results.slice.slice_type));
            break;
        case 0x07:
            ret = h264_parse_sps(ctx);
            //printf("\n");
            break;
        case 0x09:
            ret = h264_parse_aud(ctx);
            //printf("\n");
            break;
        default:
            //printf("\n");
            break;
        }
    }
    ltn_pes_packet_free(pes);
#if LOCAL_DEBUG
    printf("%s() ends\n", __func__);
#endif

    return NULL;
}

int ltntstools_h264_codec_metadata_alloc(void **hdl, uint16_t pid, uint8_t streamId)
{
    struct h264_codec_metadata_ctx_s *ctx = (struct h264_codec_metadata_ctx_s *)calloc(1, sizeof(*ctx));
    ctx->pid = pid;
    ctx->streamId = streamId;
    *hdl = NULL;

    int ret = ltntstools_pes_extractor_alloc(&ctx->pes, pid, streamId, (pes_extractor_callback)pe_callback, ctx, (4 * 1048576), (8 * 1048576));
    if (ret < 0) {
        fprintf(stderr, "%s() Unable to allocate a pes extractor\n", __func__);
        free(ctx);
        return -1;
    }
    ltntstools_pes_extractor_set_skip_data(ctx->pes, 0); /* We need the pes payload with our callback. */

    ctx->lastComplete = time(NULL);

    *hdl = ctx;
    return 0; /* Success */
}

ssize_t ltntstools_h264_codec_metadata_write(void *hdl, const uint8_t *pkt, size_t packetCount, int *complete)
{
    struct h264_codec_metadata_ctx_s *ctx = (struct h264_codec_metadata_ctx_s *)hdl;
#if 1
    time_t now = time(NULL);
    if (ctx->lastComplete + 4 == now) {
        ctx->lastComplete = now;
        ctx->parseComplete = 0;
    }

    if (ctx->parseComplete == 0) {
#endif
        ltntstools_pes_extractor_write(ctx->pes, pkt, packetCount);
    }

    *complete = ctx->parseComplete;

    return 0;
}

void ltntstools_h264_codec_metadata_free(void *hdl)
{
    struct h264_codec_metadata_ctx_s *ctx = (struct h264_codec_metadata_ctx_s *)hdl;

    ltntstools_pes_extractor_free(ctx->pes);

    free(ctx);
}

int ltntstools_h264_codec_metadata_query(void *hdl, struct h264_codec_metadata_results_s *result)
{
    struct h264_codec_metadata_ctx_s *ctx = (struct h264_codec_metadata_ctx_s *)hdl;

    memcpy(result, &ctx->results, sizeof(struct h264_codec_metadata_results_s));

    return 0;
}
