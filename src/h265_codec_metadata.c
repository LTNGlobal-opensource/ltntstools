#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libltntstools/ltntstools.h>
#include <libavutil/internal.h>
#include <libavcodec/golomb.h>
#include "codecs.h"

#define LOCAL_DEBUG 0

struct h265_codec_metadata_ctx_s
{
    /* PES extraction */
    uint16_t pid;
    uint8_t  streamId;
    void    *pes;

    /* NAL Parsing */
    GetBitContext gb;
    int parseComplete;

    /* user facing results */
    struct h265_codec_metadata_results_s results;

    time_t lastComplete;
};

#define DEBUGGER { int *p = NULL; *p = 0; }

/* A.3.2 - Main Profile - Conformance of a bitstream to the Main profile is indicated by general_profile_idc being
    * equal to 1 or general_profile_compatibility_flag[ 1 ] being equal to 1
    */

/* A.3.2 - Main 10 Profile - Conformance of a bitstream to the Main 10 profile is indicated by
    * general_profile_idc being equal to 2 or general_profile_compatibility_flag[ 2 ] being equal to 1
    */

/* A.3.4 - Main Still Picture profile - Conformance of a bitstream to the Main Still Picture
    * profile is indicated by general_profile_idc being equal to 3 or
    * general_profile_compatibility_flag[ 3 ] being equal to 1.
    */

/* TODO: More to be defined here, specifically High. */

static char *h265_profile_idc_lookup(uint32_t idc)
{
    switch (idc) {
    case 1: return "Main";
    case 2: return "Main 10";
    case 3: return "Main Still Picture";
    default: return "Unknown";
    }
}

/* Table 6-1, section 6.2 */
static char *h265_chroma_format_idc_lookup(uint32_t idc)
{
    switch (idc) {
    case 0: return "Monochrome";
    case 1: return "4:2:0";
    case 2: return "4:2:2";
    case 3: return "4:4:4";
    default: return "Unknown";
    }
}

/* 7.3.1.1 - General NAL unit syntax.
 * Long story short, the metadata SPS/PPS etc can have sequences of data that violate
 * the pes rule of N zeros followed by high bits. As a result, ALL nal sequences
 * as per the spec have to be protected against such events, and unpacked accordingly
 * by the received (remove additional stuff bytes after two consequentive zeros and a three)
 * 
 * The caller owns the lifespan of the dst buffer and is responsible for freeing it.
 */
int h265_coalesce_nal(uint8_t **dst, uint32_t *dstLengthBytes, const uint8_t *src, uint32_t srcLengthBytes)
{
    uint8_t *p = malloc(srcLengthBytes);
    if (!p)
        return -1;

    uint8_t *pb = p;

    /* in/out buffers will be formatted 00 00 01 NN NN DD DD DD DD */
    for (int i = 0; i < srcLengthBytes; i++) {
        if (i + 2 < srcLengthBytes) {
            if ((src[i + 0] == 0) && (src[i + 1] == 0) && (src[i + 2] == 3)) {
                *(p++) = *(src + i + 0);
                *(p++) = *(src + i + 1);
                i += 2;
            } else {
                *(p++) = *(src + i);
            }
        }
    }

    *dst = pb;
    *dstLengthBytes = p - pb;

    return 0; /* Success */
}

static void h265_parse_done(struct h265_codec_metadata_ctx_s *ctx)
{
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif
    ctx->parseComplete = 1;
}

static void h265_parse_restart(struct h265_codec_metadata_ctx_s *ctx)
{
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif
    ctx->parseComplete = 0;
    ctx->results.vps.valid = 0;
    ctx->results.pps.valid = 0;
    ctx->results.sps.valid = 0;
}

static int h265_parse_vui_parameters(struct h265_codec_metadata_ctx_s *ctx)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct h265_seq_parameter_set_rbsp_s *sps = &r->sps;

    sps->aspect_ratio_info_present_flag = get_bits1(&ctx->gb);
    if (sps->aspect_ratio_info_present_flag) {
        sps->aspect_ratio_idc = get_bits(&ctx->gb, 8);
        if (sps->aspect_ratio_idc == 255 /* EXTENDED_SAR */) {
            sps->sar_width = get_bits(&ctx->gb, 16);
            sps->sar_height = get_bits(&ctx->gb, 16);
        }
    }

    sps->overscan_info_present_flag = get_bits1(&ctx->gb);
    if (sps->overscan_info_present_flag) {
        sps->overscan_appropriate_flag = get_bits1(&ctx->gb);
    }

    sps->video_signal_type_present_flag = get_bits1(&ctx->gb);
    if (sps->video_signal_type_present_flag) {
        sps->video_format = get_bits(&ctx->gb, 3);
        sps->video_full_range_flag = get_bits1(&ctx->gb);
        sps->colour_description_present_flag = get_bits1(&ctx->gb);
        if (sps->colour_description_present_flag) {
            sps->colour_primaries = get_bits(&ctx->gb, 8);
            sps->transfer_characteristics = get_bits(&ctx->gb, 8);
            sps->matrix_coeffs = get_bits(&ctx->gb, 8);
        }
    }

    sps->chroma_loc_info_present_flag = get_bits1(&ctx->gb);
    if (sps->chroma_loc_info_present_flag) {
        sps->chroma_sample_loc_type_top_field = get_ue_golomb(&ctx->gb);
        sps->chroma_sample_loc_type_bottom_field = get_ue_golomb(&ctx->gb);
    }

    sps->neutral_chroma_indication_flag = get_bits1(&ctx->gb);
    sps->field_seq_flag = get_bits1(&ctx->gb);
    sps->frame_field_info_present_flag = get_bits1(&ctx->gb);
    sps->default_display_window_flag = get_bits1(&ctx->gb);
    if (sps->default_display_window_flag) {
        sps->def_disp_win_left_offset = get_ue_golomb(&ctx->gb);
        sps->def_disp_win_right_offset = get_ue_golomb(&ctx->gb);
        sps->def_disp_win_top_offset = get_ue_golomb(&ctx->gb);
        sps->def_disp_win_bottom_offset = get_ue_golomb(&ctx->gb);
    }

    sps->vui_timing_info_present_flag = get_bits1(&ctx->gb);
    //printf("sps->vui_timing_info_present_flag = %d\n", sps->vui_timing_info_present_flag);
    if (sps->vui_timing_info_present_flag) {
        sps->vui_num_units_in_tick = get_bits_long(&ctx->gb, 32);
        sps->vui_time_scale = get_bits_long(&ctx->gb, 32);
        //printf("sps->vui_num_units_in_tick = %d\n", sps->vui_num_units_in_tick);
        //printf("sps->vui_time_scale = %d\n", sps->vui_time_scale);

        sps->vui_poc_proportional_to_timing_flag = get_bits1(&ctx->gb);
        if (sps->vui_poc_proportional_to_timing_flag) {
            sps->vui_num_ticks_poc_diff_one_minus1 = get_ue_golomb(&ctx->gb);
        }
        //sps->vui_hrd_parameters_present_flag = get_bits1(&ctx->gb);
    }



    return 0; /* Success */
}

/*
 * 7.3.7 - Short-term reference picture set syntax
 * We stack these bits and don't put them in a content, we don't care.
 */
static int h265_parse_st_ref_pic_set(struct h265_codec_metadata_ctx_s *ctx, int stRpsIdx)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct h265_seq_parameter_set_rbsp_s *sps = &r->sps;


    int NumDeltaPocs[32] = { 0 };

    if (stRpsIdx != 0) {
        sps->inter_ref_pic_set_prediction_flag = get_bits1(&ctx->gb);
    }

    if (sps->inter_ref_pic_set_prediction_flag) {
        if (stRpsIdx == sps->num_short_term_ref_pic_sets) {
            sps->delta_idx_minus1 = get_ue_golomb(&ctx->gb);
        }

        int RefRpsIdx = stRpsIdx - ( sps->delta_idx_minus1 + 1 );

        sps->delta_rps_sign = get_bits1(&ctx->gb);
        sps->abs_delta_rps_minus1 = get_ue_golomb(&ctx->gb);
        for (int j = 0; j <= NumDeltaPocs[RefRpsIdx]; j++) {
            sps->used_by_curr_pic_flag = get_bits1(&ctx->gb);
            if (!sps->used_by_curr_pic_flag) {
                sps->use_delta_flag = get_bits1(&ctx->gb);
            }
        }
    } else {
        sps->num_negative_pics = get_ue_golomb(&ctx->gb);
        sps->num_positive_pics = get_ue_golomb(&ctx->gb);
        for(int i = 0; i < sps->num_negative_pics; i++) {
            sps->delta_poc_s0_minus1 = get_ue_golomb(&ctx->gb);
            sps->used_by_curr_pic_s0_flag = get_bits1(&ctx->gb);
        }
        for (int i = 0; i < sps->num_positive_pics; i++) {
            sps->delta_poc_s1_minus1 = get_ue_golomb(&ctx->gb);
            sps->used_by_curr_pic_s1_flag = get_bits1(&ctx->gb);
        }

        NumDeltaPocs[ stRpsIdx ] = sps->num_negative_pics + sps->num_positive_pics;

    }


    return 0; /* Success */
}

#define MIN(a,b) (((a)<(b))?(a):(b))
static int h265_parse_scaling_list_data(struct h265_codec_metadata_ctx_s *ctx)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct h265_seq_parameter_set_rbsp_s *sps = &r->sps;

    int nextCoef;
    int scaling_list_delta_coef;

    for (int sizeId = 0; sizeId < 4; sizeId++) {

        for (int matrixId = 0; matrixId < 6; matrixId += ( sizeId == 3 ) ? 3 : 1 ) {

            sps->scaling_list_pred_mode_flag[sizeId][matrixId] = get_bits1(&ctx->gb);

            if (!sps->scaling_list_pred_mode_flag[sizeId][matrixId]) {

                sps->scaling_list_pred_matrix_id_delta[sizeId][matrixId] = get_ue_golomb(&ctx->gb);

            } else {

                nextCoef = 8;
                int coefNum = MIN(64,(1 << (4+(sizeId << 1))));

                if (sizeId > 1) {
                    sps->scaling_list_dc_coef_minus8[sizeId - 2][matrixId] = get_se_golomb(&ctx->gb);
                    nextCoef = sps->scaling_list_dc_coef_minus8[sizeId - 2][matrixId] + 8;
                }

                for (int i = 0; i < coefNum; i++) {
                    scaling_list_delta_coef = get_se_golomb(&ctx->gb);
                    nextCoef = ( nextCoef + scaling_list_delta_coef + 256 ) % 256;
                    //Todo:
                    //ScalingList[sizeId][matrixId][i] = nextCoef;
                }

            }
        }

    }

    return 0; /* Success */
}

/* 7.3.3 - Profile, tier and level syntax */
static int h265_parse_profile_tier_level(struct h265_codec_metadata_ctx_s *ctx, struct h265_profile_tier_level_s *p, int profilePresentFlag, int maxNumSubLayersMinus1)
{
    if (profilePresentFlag) {
        p->general_profile_space = get_bits(&ctx->gb, 2);
        p->general_tier_flag = get_bits1(&ctx->gb);
        p->general_profile_idc = get_bits(&ctx->gb, 5);

        /* A.3.2 - Main Profile - Conformance of a bitstream to the Main profile is indicated by general_profile_idc being
         * equal to 1 or general_profile_compatibility_flag[ 1 ] being equal to 1
         */

        /* A.3.2 - Main 10 Profile - Conformance of a bitstream to the Main 10 profile is indicated by
         * general_profile_idc being equal to 2 or general_profile_compatibility_flag[ 2 ] being equal to 1
         */

        /* A.3.4 - Main Still Picture profile - Conformance of a bitstream to the Main Still Picture
         * profile is indicated by general_profile_idc being equal to 3 or
         * general_profile_compatibility_flag[ 3 ] being equal to 1.
         */

        //printf("general_profile_idc = %d\n", p->general_profile_idc);

        for (int j = 0; j < 32; j++) {
            p->general_profile_compatibility_flag[j] = get_bits1(&ctx->gb);
        }

        p->general_progressive_source_flag = get_bits1(&ctx->gb);
        p->general_interlaced_source_flag = get_bits1(&ctx->gb);
        p->general_non_packed_constraint_flag = get_bits1(&ctx->gb);
        p->general_frame_only_constraint_flag = get_bits1(&ctx->gb);

        if (p->general_profile_idc == 4 || p->general_profile_compatibility_flag[ 4 ] ||
            p->general_profile_idc == 5 || p->general_profile_compatibility_flag[ 5 ] ||
            p->general_profile_idc == 6 || p->general_profile_compatibility_flag[ 6 ] ||
            p->general_profile_idc == 7 || p->general_profile_compatibility_flag[ 7 ] ||
            p->general_profile_idc == 8 || p->general_profile_compatibility_flag[ 8 ] ||
            p->general_profile_idc == 9 || p->general_profile_compatibility_flag[ 9 ] ||
            p->general_profile_idc == 10 || p->general_profile_compatibility_flag[ 10 ])
        {
            p->general_max_12bit_constraint_flag = get_bits1(&ctx->gb);
            p->general_max_10bit_constraint_flag = get_bits1(&ctx->gb);
            p->general_max_8bit_constraint_flag = get_bits1(&ctx->gb);
            p->general_max_422chroma_constraint_flag = get_bits1(&ctx->gb);
            p->general_max_420chroma_constraint_flag = get_bits1(&ctx->gb);
            p->general_max_monochrome_constraint_flag = get_bits1(&ctx->gb);
            p->general_intra_constraint_flag = get_bits1(&ctx->gb);
            p->general_one_picture_only_constraint_flag = get_bits1(&ctx->gb);
            p->general_lower_bit_rate_constraint_flag = get_bits1(&ctx->gb);
            if (p->general_profile_idc == 5 || p->general_profile_compatibility_flag[ 5 ] ||
                p->general_profile_idc == 9 || p->general_profile_compatibility_flag[ 9 ] ||
                p->general_profile_idc == 10 || p->general_profile_compatibility_flag[ 10 ])
            {
                p->general_max_14bit_constraint_flag = get_bits1(&ctx->gb);

                /* Skip 33 reserved bits */
                skip_bits(&ctx->gb,  1);
                skip_bits(&ctx->gb, 16);
                skip_bits(&ctx->gb, 16);
            } else {
                /* Skip 34 reserved bits */
                skip_bits(&ctx->gb,  2);
                skip_bits(&ctx->gb, 16);
                skip_bits(&ctx->gb, 16);
            }

        } else {
            /* Skip 43 reserved bits */
            skip_bits(&ctx->gb, 11);
            skip_bits(&ctx->gb, 16);
            skip_bits(&ctx->gb, 16);
        }

        if ((p->general_profile_idc >= 1 && p->general_profile_idc <= 5) ||
            p->general_profile_idc == 9 ||
            p->general_profile_compatibility_flag[ 1 ] || p->general_profile_compatibility_flag[ 2 ] ||
            p->general_profile_compatibility_flag[ 3 ] || p->general_profile_compatibility_flag[ 4 ] ||
            p->general_profile_compatibility_flag[ 5 ] || p->general_profile_compatibility_flag[ 9 ])
        {
            p->general_inbld_flag = get_bits1(&ctx->gb);
        } else {
            /* Skip 1 reserved bit */
            skip_bits(&ctx->gb, 1);
        }

        /* general_level_idc and sub_layer_level_idc[ i ] shall be set
         * equal to a value of 30 times the level number specified in Table A.6.
         */
        p->general_level_idc = get_bits(&ctx->gb, 8);
        //printf("general_level_idc = %d\n", p->general_level_idc);

        for (int i = 0; i < maxNumSubLayersMinus1; i++) {
            struct h265_profile_tier_level_sub_layer_s *sl = &p->sublayer[i];
            sl->sub_layer_profile_present_flag = get_bits1(&ctx->gb);
            sl->sub_layer_level_present_flag = get_bits1(&ctx->gb);
        }

        if (maxNumSubLayersMinus1 > 0) {
            for (int i = maxNumSubLayersMinus1; i < 8; i++) {
                /* Skip 2 reserved bits */
                skip_bits(&ctx->gb, 2);
            }
        }

        for (int i = 0; i < maxNumSubLayersMinus1; i++) {
            struct h265_profile_tier_level_sub_layer_s *sl = &p->sublayer[i];
            if (sl->sub_layer_profile_present_flag) {
                sl->sub_layer_profile_space = get_bits(&ctx->gb, 2);
                sl->sub_layer_tier_flag = get_bits1(&ctx->gb);
                sl->sub_layer_profile_idc = get_bits(&ctx->gb, 5);
                for (int j = 0; j < 32; j++) {
                    sl->sub_layer_profile_compatibility_flag[j] = get_bits1(&ctx->gb);
                }
                sl->sub_layer_progressive_source_flag = get_bits1(&ctx->gb);
                sl->sub_layer_interlaced_source_flag = get_bits1(&ctx->gb);
                sl->sub_layer_non_packed_constraint_flag = get_bits1(&ctx->gb);
                sl->sub_layer_frame_only_constraint_flag = get_bits1(&ctx->gb);

                if (sl->sub_layer_profile_idc == 4 || sl->sub_layer_profile_compatibility_flag[ 4 ] ||
                    sl->sub_layer_profile_idc == 5 || sl->sub_layer_profile_compatibility_flag[ 5 ] ||
                    sl->sub_layer_profile_idc == 6 || sl->sub_layer_profile_compatibility_flag[ 6 ] ||
                    sl->sub_layer_profile_idc == 7 || sl->sub_layer_profile_compatibility_flag[ 7 ] ||
                    sl->sub_layer_profile_idc == 8 || sl->sub_layer_profile_compatibility_flag[ 8 ] ||
                    sl->sub_layer_profile_idc == 9 || sl->sub_layer_profile_compatibility_flag[ 9 ] ||
                    sl->sub_layer_profile_idc == 10 || sl->sub_layer_profile_compatibility_flag[ 10 ])
                {
                    sl->sub_layer_max_12bit_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_max_10bit_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_max_8bit_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_max_422chroma_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_max_420chroma_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_max_monochrome_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_intra_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_one_picture_only_constraint_flag = get_bits1(&ctx->gb);
                    sl->sub_layer_lower_bit_rate_constraint_flag = get_bits1(&ctx->gb);

                    if (sl->sub_layer_profile_idc == 5 || sl->sub_layer_profile_compatibility_flag[ 5 ]) {
                        sl->sub_layer_max_14bit_constraint_flag = get_bits1(&ctx->gb);
                        /* Skip 33 reserved bits */
                        skip_bits(&ctx->gb,  1);
                        skip_bits(&ctx->gb, 16);
                        skip_bits(&ctx->gb, 16);
                    } else {
                        /* Skip 34 reserved bits */
                        skip_bits(&ctx->gb,  2);
                        skip_bits(&ctx->gb, 16);
                        skip_bits(&ctx->gb, 16);
                    }
                } else {
                    /* skip 43 reserved bits */
                    skip_bits(&ctx->gb, 11);
                    skip_bits(&ctx->gb, 16);
                    skip_bits(&ctx->gb, 16);
                }

                if ((sl->sub_layer_profile_idc >= 1 && sl->sub_layer_profile_idc <= 5) ||
                    sl->sub_layer_profile_idc == 9 ||
                    sl->sub_layer_profile_compatibility_flag[ 1 ] ||
                    sl->sub_layer_profile_compatibility_flag[ 2 ] ||
                    sl->sub_layer_profile_compatibility_flag[ 3 ] ||
                    sl->sub_layer_profile_compatibility_flag[ 4 ] ||
                    sl->sub_layer_profile_compatibility_flag[ 5 ] ||
                    sl->sub_layer_profile_compatibility_flag[ 9 ])
                {
                    sl->sub_layer_inbld_flag = get_bits1(&ctx->gb);
                } else {
                    /* skip 1 reserved bit */
                    skip_bits(&ctx->gb, 1);
                }
            } /* if (sl->sub_layer_profile_present_flag) { */
            if (sl->sub_layer_level_present_flag) {
                sl->sub_layer_level_idc = get_bits(&ctx->gb, 8);
            }
        } /* For all sublayers */
    } /* if (profilePresentFlag) */

    return 0; /* Success */
}

/* 7.3.2.9 Slice segment layer RBSP syntax */
static int h265_parse_slice_segment_layer(struct h265_codec_metadata_ctx_s *ctx, uint32_t nalType)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct h265_seq_parameter_set_rbsp_s *sps = &r->sps;
    struct h265_pic_parameter_set_rbsp_s *pps = &r->pps;
    struct h265_video_parameter_set_rbsp_s *vps = &r->vps;

#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    if ((vps->valid == 0) || (sps->valid == 0) || (pps->valid == 0))
        return -1; /* Awaiting dependency metadata */

    int first_slice_segment_in_pic_flag = get_bits1(&ctx->gb);
    if ((nalType >= 16) && (nalType <= 23)) {
        int no_output_of_prior_pics_flag = get_bits1(&ctx->gb);
        if (no_output_of_prior_pics_flag) { }
        //printf("no_output_of_prior_pics_flag = %d\n", no_output_of_prior_pics_flag);
    }

    int slice_pic_parameter_set_id = get_ue_golomb(&ctx->gb);
    if (slice_pic_parameter_set_id) { }
    //printf("slice_pic_parameter_set_id = %d\n", slice_pic_parameter_set_id);

    int dependent_slice_segment_flag = 0;
    if (!first_slice_segment_in_pic_flag) {
        if (pps->dependent_slice_segments_enabled_flag) {
            dependent_slice_segment_flag = get_bits(&ctx->gb, 1);
        }
        int slice_address_length = 0; //av_ceil_log2(s->ps.sps->ctb_width * s->ps.sps->ctb_height);
        int slice_segment_address = get_bitsz(&ctx->gb, slice_address_length);
        if (slice_segment_address) { }
        //printf("slice_segment_address = %d\n", slice_segment_address);
    }

    int slice_type = -1;
    if (!dependent_slice_segment_flag) {
        for (int i = 0; i < pps->num_extra_slice_header_bits; i++) {
            skip_bits(&ctx->gb, 1); /* Reserved */
        }
        slice_type = get_ue_golomb(&ctx->gb);
        #if 0
        printf("slice_type = %d (%s)\n", slice_type,
            slice_type == 0 ? "B" :
            slice_type == 1 ? "P" :
            slice_type == 2 ? "I" : "?");
        #endif
        /* Abort parsing */
    }
    if (slice_type == -1) {

    }
    /* Abort parsing */

    h265_parse_done(ctx);

    return 0; /* Success */
}

/* VPS - 7.3.2.1 Video parameter set RBSP syntax */
static int h265_parse_vps(struct h265_codec_metadata_ctx_s *ctx)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct h265_video_parameter_set_rbsp_s *vps = &r->vps;
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    vps->vps_video_parameter_set_id = get_bits(&ctx->gb, 4);
    vps->vps_base_layer_internal_flag = get_bits1(&ctx->gb);
    vps->vps_base_layer_available_flag = get_bits1(&ctx->gb);
    vps->vps_max_layers_minus1 = get_bits(&ctx->gb, 6);
    vps->vps_max_sub_layers_minus1 = get_bits(&ctx->gb, 3);
    vps->vps_temporal_id_nesting_flag = get_bits1(&ctx->gb);
    skip_bits(&ctx->gb, 16);

    h265_parse_profile_tier_level(ctx, &ctx->results.vps.ptl, 1, vps->vps_max_layers_minus1);

    vps->vps_sub_layer_ordering_info_present_flag = get_bits1(&ctx->gb);

    for (int i = ( vps->vps_sub_layer_ordering_info_present_flag ? 0 : vps->vps_max_sub_layers_minus1 );
        i <= vps->vps_max_sub_layers_minus1; i++)
    {
        vps->vps_max_dec_pic_buffering_minus1[i] = get_ue_golomb(&ctx->gb);
        vps->vps_max_num_reorder_pics[i] = get_ue_golomb(&ctx->gb);
        vps->vps_max_latency_increase_plus1[i] = get_ue_golomb(&ctx->gb);
    }

    vps->vps_max_layer_id = get_bits(&ctx->gb, 6);
    vps->vps_num_layer_sets_minus1 = get_ue_golomb(&ctx->gb);

    for (int i = 1; i <= vps->vps_num_layer_sets_minus1; i++) {
        for (int j = 0; j <= vps->vps_max_layer_id; j++) {
            //vps->layer_id_included_flag[;] TODO, we don't handle this well.
            skip_bits(&ctx->gb, 1);
        }
    }

    vps->vps_timing_info_present_flag = get_bits1(&ctx->gb);
    if (vps->vps_timing_info_present_flag) {
        vps->vps_num_units_in_tick = get_bits_long(&ctx->gb, 32);
        vps->vps_time_scale = get_bits_long(&ctx->gb, 32);
        vps->vps_poc_proportional_to_timing_flag = get_bits1(&ctx->gb);
        if (vps->vps_poc_proportional_to_timing_flag) {
           vps->vps_num_ticks_poc_diff_one_minus1  = get_ue_golomb(&ctx->gb);
        }
        vps->vps_num_hrd_parameters = get_ue_golomb(&ctx->gb);

        /* Aborting parsing here */
    }
    /* Aborting parsing here */

    //printf("vps.vps_timing_info_present_flag = %d\n", vps->vps_timing_info_present_flag);
    if (vps->vps_timing_info_present_flag) {
       // printf("vps.vps_num_units_in_tick = %d\n", vps->vps_num_units_in_tick);
        //printf("vps.vps_time_scale = %d\n", vps->vps_time_scale);
    }

    vps->valid = 1;
    /* Abort parsing */

    return 0; /* Success */
}

/* SPS - 7.3.2.2.1 General sequence parameter set RBSP syntax */
static int h265_parse_sps(struct h265_codec_metadata_ctx_s *ctx)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct h265_seq_parameter_set_rbsp_s *sps = &r->sps;
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    /* We need to query a couple of fields before we can decode
        * a slice segment header to extract the slice type.
        */
    if (sps->valid)
        return -1; /* Already have the data */

    sps->sps_video_parameter_set_id = get_bits(&ctx->gb, 4);
    sps->sps_max_sub_layers_minus1 = get_bits(&ctx->gb, 3);
    sps->sps_temporal_id_nesting_flag = get_bits1(&ctx->gb);

    h265_parse_profile_tier_level(ctx, &ctx->results.sps.ptl, 1, sps->sps_max_sub_layers_minus1);

    sps->sps_seq_parameter_set_id = get_ue_golomb(&ctx->gb);
    sps->chroma_format_idc = get_ue_golomb(&ctx->gb);
    if (sps->chroma_format_idc == 3) {
        sps->separate_colour_plane_flag = get_bits1(&ctx->gb);
    }

    sps->pic_width_in_luma_samples = get_ue_golomb(&ctx->gb);
    sps->pic_height_in_luma_samples = get_ue_golomb(&ctx->gb);

    sps->conformance_window_flag = get_bits1(&ctx->gb);
    if (sps->conformance_window_flag) {
        sps->conf_win_left_offset = get_ue_golomb(&ctx->gb);
        sps->conf_win_right_offset = get_ue_golomb(&ctx->gb);
        sps->conf_win_top_offset = get_ue_golomb(&ctx->gb);
        sps->conf_win_bottom_offset = get_ue_golomb(&ctx->gb);
    }

    sps->bit_depth_luma_minus8 = get_ue_golomb(&ctx->gb);
    sps->bit_depth_chroma_minus8 = get_ue_golomb(&ctx->gb);
    sps->log2_max_pic_order_cnt_lsb_minus4 = get_ue_golomb(&ctx->gb);
    sps->sps_sub_layer_ordering_info_present_flag = get_bits1(&ctx->gb);
    for (int i = (sps->sps_sub_layer_ordering_info_present_flag ? 0 : sps->sps_max_sub_layers_minus1 );
        i <= sps->sps_max_sub_layers_minus1; i++)
    {
        sps->sps_max_dec_pic_buffering_minus1[i] = get_ue_golomb(&ctx->gb);
        sps->sps_max_num_reorder_pics[i] = get_ue_golomb(&ctx->gb);
        sps->sps_max_latency_increase_plus1[i] = get_ue_golomb(&ctx->gb);
    }

    sps->log2_min_luma_coding_block_size_minus3 = get_ue_golomb(&ctx->gb);
    sps->log2_diff_max_min_luma_coding_block_size = get_ue_golomb(&ctx->gb);
    sps->log2_min_luma_transform_block_size_minus2 = get_ue_golomb(&ctx->gb);
    sps->log2_diff_max_min_luma_transform_block_size  = get_ue_golomb(&ctx->gb);
    sps->max_transform_hierarchy_depth_inter = get_ue_golomb(&ctx->gb);
    sps->max_transform_hierarchy_depth_intra = get_ue_golomb(&ctx->gb);
    sps->scaling_list_enabled_flag = get_bits1(&ctx->gb);

    if (sps->scaling_list_enabled_flag) {
        sps->sps_scaling_list_data_present_flag = get_bits1(&ctx->gb);
        h265_parse_scaling_list_data(ctx);
    }

    sps->amp_enabled_flag = get_bits1(&ctx->gb);
    sps->sample_adaptive_offset_enabled_flag = get_bits1(&ctx->gb);
    sps->pcm_enabled_flag = get_bits1(&ctx->gb);
    if (sps->pcm_enabled_flag) {
        sps->pcm_sample_bit_depth_luma_minus1 = get_bits(&ctx->gb, 4);
        sps->pcm_sample_bit_depth_chroma_minus1 = get_bits(&ctx->gb, 4);
        sps->log2_min_pcm_luma_coding_block_size_minus3 = get_ue_golomb(&ctx->gb);
        sps->log2_diff_max_min_pcm_luma_coding_block_size = get_ue_golomb(&ctx->gb);
        sps->pcm_loop_filter_disabled_flag = get_bits1(&ctx->gb);
    }

    sps->num_short_term_ref_pic_sets = get_ue_golomb(&ctx->gb);
    for (int i = 0; i < sps->num_short_term_ref_pic_sets; i++) {
        h265_parse_st_ref_pic_set(ctx, i);
    }

    sps->long_term_ref_pics_present_flag = get_bits1(&ctx->gb);
    if (sps->long_term_ref_pics_present_flag) {
        sps->num_long_term_ref_pics_sps = get_ue_golomb(&ctx->gb);
        for (int i = 0; i < sps->num_long_term_ref_pics_sps; i++) {
            sps->lt_ref_pic_poc_lsb_sps[i] = get_ue_golomb(&ctx->gb);
            sps->used_by_curr_pic_lt_sps_flag[i] = get_bits1(&ctx->gb);
        }
    }

    sps->sps_temporal_mvp_enabled_flag = get_bits1(&ctx->gb);
    sps->strong_intra_smoothing_enabled_flag = get_bits1(&ctx->gb);
    sps->vui_parameters_present_flag = get_bits1(&ctx->gb);
    if (sps->vui_parameters_present_flag) {
        h265_parse_vui_parameters(ctx);
    }

    sps->valid = 1;
    /* Abort parsing */

    strcpy(&r->profile_idc_ascii[0], h265_profile_idc_lookup(sps->ptl.general_profile_idc));
    strcpy(&r->chroma_format_idc_ascii[0], h265_chroma_format_idc_lookup(sps->chroma_format_idc));
    sprintf(&r->bit_depth_luma_ascii[0], "%dbit", sps->bit_depth_luma_minus8 + 8);
    sprintf(&r->level_idc_ascii[0], "%.1f", (double)sps->ptl.general_level_idc / 30.0);

    if (sps->vui_timing_info_present_flag) {
        sprintf(&r->timing_info_fps_ascii[0], "%.2ffps fixed",
            (double)sps->vui_time_scale / (double)sps->vui_num_units_in_tick);
    } else {
        r->timing_info_fps_ascii[0] = 0;
    }

    sprintf(&r->video_colorspace_ascii[0], "%s profile %s, %s, %s",
        r->profile_idc_ascii,
        r->level_idc_ascii,
        r->chroma_format_idc_ascii,
        r->bit_depth_luma_ascii);

    sprintf(&r->video_format_ascii[0], "%dx%d %s",
        sps->pic_width_in_luma_samples, sps->pic_height_in_luma_samples,
        r->timing_info_fps_ascii);

#if LOCAL_DEBUG
    printf("sps.video_colorspace    = %s\n", r->video_colorspace_ascii);
    printf("sps.video_format        = %s\n", r->video_format_ascii);
    printf("sps.general_profile_idc = %d [%s]\n", sps->ptl.general_profile_idc, r->profile_idc_ascii);
    printf("sps.general_level_idc   = %d [%s]\n", sps->ptl.general_level_idc, r->level_idc_ascii);
    printf("sps.chroma_format_idc   = %d [%s]\n", sps->chroma_format_idc, r->chroma_format_idc_ascii);
    printf("sps.bit_depth_luma      = %d [%s]\n", sps->bit_depth_luma_minus8 + 8, r->bit_depth_luma_ascii);
    printf("sps.vui_timing_info     = %d/%d [%s]\n", sps->vui_time_scale,
        sps->vui_num_units_in_tick, r->timing_info_fps_ascii);
#endif
    return 0; /* Success */
}

/* PPS - 7.3.2.3.1 General picture parameter set RBSP syntax */
static int h265_parse_pps(struct h265_codec_metadata_ctx_s *ctx)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct h265_pic_parameter_set_rbsp_s *pps = &r->pps;
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    /* We need to query a couple of fields before we can decode
        * a slice segment header to extract the slice type.
        * Find the num_extra_slice_header_bits field.
        */
    if (pps->valid)
        return -1; /* Already have the data */

    pps->pps_pic_parameter_set_id = get_ue_golomb(&ctx->gb);
    pps->pps_seq_parameter_set_id = get_ue_golomb(&ctx->gb);
    pps->dependent_slice_segments_enabled_flag = get_bits1(&ctx->gb);
    pps->output_flag_present_flag = get_bits1(&ctx->gb);
    pps->num_extra_slice_header_bits = get_bits(&ctx->gb, 3);

    pps->valid = 1;
    /* Abort parsing */

    return 0; /* Success */
}

/* AUD - 7.3.2.5 Access unit delimiter RBSP syntax */
static int h265_parse_aud(struct h265_codec_metadata_ctx_s *ctx)
{
    struct h265_codec_metadata_results_s *r = &ctx->results;
    struct access_unit_delimiter_rbsp *aud = &r->aud;
#if LOCAL_DEBUG
    printf("%s()\n", __func__);
#endif

    aud->pic_type = get_bits(&ctx->gb, 3);

#if LOCAL_DEBUG
    printf("aud.pic_type = %s (%02x)\n",
            aud->pic_type == 0 ? "I" :
            aud->pic_type == 1 ? "P,I" :
            aud->pic_type == 2 ? "B,P,I" :
            "Illegal value",
            aud->pic_type
    );
#endif

    return 0; /* Success */
}

static void *pe_callback(void *userContext, struct ltn_pes_packet_s *pes)
{
    struct h265_codec_metadata_ctx_s *ctx = (struct h265_codec_metadata_ctx_s *)userContext;

#if LOCAL_DEBUG
    printf("%s() begins\n", __func__);
#endif

    /* Pes payload may contain zero or more complete H264 nals. */ 
    int offset = -1;
    while (1) {
        int ret = ltn_nal_h265_findHeader(pes->data, pes->dataLengthBytes, &offset);
        if (ret < 0) {
            break;
        }

  		unsigned int nalType = (pes->data[offset + 3] >> 1) & 0x3f;

#if LOCAL_DEBUG
		const char *nalName = h265Nals_lookupName(nalType);

        printf("H.265/HEVC: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x ", *(pes->data + offset + i));
        }
        printf(": NalType %02d : %s\n", nalType, nalName);
#endif
        
        /* NAL header is two bytes */
        //int r = init_get_bits8(&ctx->gb, pes->data + offset + 4 + 1, pes->dataLengthBytes - (offset + 4 + 1));
        init_get_bits8(&ctx->gb, pes->data + offset + 4 + 1, 256);

        switch (nalType) {
        case  0: /* TRAIL_N - slice_segment_layer_rbsp */
        case  1: /* TRAIL_R - slice_segment_layer_rbsp */
        case  2: /* TSA_N - slice_segment_layer_rbsp */
        case  3: /* TSA_R - slice_segment_layer_rbsp */
        case  4: /* STSA_N - slice_segment_layer_rbsp */
        case  5: /* STSA_R - slice_segment_layer_rbsp */
        case  6: /* RADL_N - slice_segment_layer_rbsp */
        case  7: /* RADL_R - slice_segment_layer_rbsp */
        case  8: /* RASL_N - slice_segment_layer_rbsp */
        case  9: /* RASL_R - slice_segment_layer_rbsp */
        case 16:
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
            ret = h265_parse_slice_segment_layer(ctx, nalType);
            break;
        case 32: /* VPS */
            ret = h265_parse_vps(ctx);
            break;
        case 33: /* SPS */
        {
            uint8_t *buf = NULL;
            uint32_t bufLengthBytes;
            h265_coalesce_nal(&buf, &bufLengthBytes, pes->data + offset, 256);
            init_get_bits8(&ctx->gb, buf + 5, 256 - 5);
#if 0
            printf("       new: ");
            for (int i = 0; i < 42; i++) {
                printf("%02x ", *(buf + i));
            }
#endif
            ret = h265_parse_sps(ctx);
            free(buf);
        }
            break;
        case 34: /* PPS */
            ret = h265_parse_pps(ctx);
            break;
        case 35: /* AUD */
            ret = h265_parse_aud(ctx);
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

int ltntstools_h265_codec_metadata_alloc(void **hdl, uint16_t pid, uint8_t streamId)
{
    struct h265_codec_metadata_ctx_s *ctx = (struct h265_codec_metadata_ctx_s *)calloc(1, sizeof(*ctx));
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

    h265_parse_restart(ctx);

    *hdl = ctx;
    return 0; /* Success */
}

ssize_t ltntstools_h265_codec_metadata_write(void *hdl, const uint8_t *pkt, size_t packetCount, int *complete)
{
    struct h265_codec_metadata_ctx_s *ctx = (struct h265_codec_metadata_ctx_s *)hdl;
#if LOCAL_DEBUG
    //printf("%s()\n", __func__);
#endif

    time_t now = time(NULL);
    if (ctx->lastComplete + 4 == now) {
        ctx->lastComplete = now;
        h265_parse_restart(ctx);
    }

    if (ctx->parseComplete == 0) {
        ltntstools_pes_extractor_write(ctx->pes, pkt, packetCount);
    }

    *complete = ctx->parseComplete;

    return 0;
}

void ltntstools_h265_codec_metadata_free(void *hdl)
{
    struct h265_codec_metadata_ctx_s *ctx = (struct h265_codec_metadata_ctx_s *)hdl;

    ltntstools_pes_extractor_free(ctx->pes);

    free(ctx);
}

int ltntstools_h265_codec_metadata_query(void *hdl, struct h265_codec_metadata_results_s *result)
{
    struct h265_codec_metadata_ctx_s *ctx = (struct h265_codec_metadata_ctx_s *)hdl;

    memcpy(result, &ctx->results, sizeof(struct h265_codec_metadata_results_s));

    return 0;
}
