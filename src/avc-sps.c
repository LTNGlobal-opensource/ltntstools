/* Copyright Kernel Labs Inc 2015-2018 */

#include "avc-types.h"

#include <libltntstools/nal_bitreader.h>

struct avc_seq_parameter_set_s *avc_seq_parameter_set_alloc()
{
    return calloc(1, sizeof(struct avc_seq_parameter_set_s));
}

void avc_seq_parameter_set_free(struct avc_seq_parameter_set_s *sps)
{
    free(sps);
}

static int avc_seq_parameter_hrd_parse(NALBitReader *br, struct avc_hrd_parameters_s *hrd)
{
    hrd->cpb_cnt_minus1 = NALBitReader_read_ue(br);
    hrd->bit_rate_scale = NALBitReader_read_bits(br, 4);
    hrd->cpb_size_scale = NALBitReader_read_bits(br, 4);

    for (uint32_t SchedSelIdx = 0; SchedSelIdx <= hrd->cpb_cnt_minus1; SchedSelIdx++) {
        hrd->cpb_array[SchedSelIdx].bit_rate_value_minus1 = NALBitReader_read_ue(br);
        hrd->cpb_array[SchedSelIdx].cpb_size_value_minus1 = NALBitReader_read_ue(br);
        hrd->cpb_array[SchedSelIdx].cbr_flag              = NALBitReader_read_bits(br, 1);
    }

    hrd->initial_cpb_removal_delay_length_minus1 = NALBitReader_read_bits(br, 5);
    hrd->cpb_removal_delay_length_minus1         = NALBitReader_read_bits(br, 5);
    hrd->dpb_output_delay_length_minus1          = NALBitReader_read_bits(br, 5);
    hrd->time_offset_length                      = NALBitReader_read_bits(br, 5);

    return 0; /* Success */
}

/* See ISO/IEC 14496-10:2014(E) - 7.3.2.1.1.1 Scaling list syntax */
void scaling_list(NALBitReader *br, struct avc_seq_parameter_set_s *sps, uint32_t *scaling_list, int sizeOfScalingList, uint32_t *useDefaultScalingMatrixFlag)
{
    int lastScale = 8;
    int nextScale = 8;

    for (int j = 0; j < sizeOfScalingList; j++) {
        if (nextScale != 0) {
            int delta_scale = NALBitReader_read_ue(br);
            nextScale = (lastScale + delta_scale + 256) % 256;
            *useDefaultScalingMatrixFlag = (j == 0 && nextScale == 0);
        }
        *(scaling_list + j) = (nextScale == 0) ? lastScale : nextScale;
        lastScale = *(scaling_list + j);
    }
}

/* See ISO/IEC 14496-10:2014(E) - 7.3.2.1.1 Sequence parameter set data syntax */

/* This ALWAYS assumes the RBP stripped has taken place BEFORE hand,
 * See ltn_nal_h264_strip_emulation_prevention(struct ltn_nal_headers_s *h) if you need that.
 */
int avc_seq_parameter_parse(struct avc_seq_parameter_set_s *sps, const uint8_t *buf, int lengthBytes)
{
    NALBitReader sbr, *br = &sbr;

    NALBitReader_init(br, buf, lengthBytes);

    memset(sps, 0, sizeof(*sps));

    sps->profile_idc          = NALBitReader_read_bits(br, 8);
    sps->constraint_set0_flag = NALBitReader_read_bits(br, 1);
    sps->constraint_set1_flag = NALBitReader_read_bits(br, 1);
    sps->constraint_set2_flag = NALBitReader_read_bits(br, 1);
    sps->constraint_set3_flag = NALBitReader_read_bits(br, 1);
    sps->constraint_set4_flag = NALBitReader_read_bits(br, 1);
    sps->constraint_set5_flag = NALBitReader_read_bits(br, 1);

    sps->reserved_zero_2bits  = NALBitReader_read_bits(br, 2);
    sps->level_idc            = NALBitReader_read_bits(br, 8);
    sps->seq_parameter_set_id = NALBitReader_read_ue(br);

    if (sps->profile_idc == 100 || sps->profile_idc == 110 ||
        sps->profile_idc == 122 || sps->profile_idc == 244 || sps->profile_idc == 44 ||
        sps->profile_idc == 83 || sps->profile_idc == 86 || sps->profile_idc == 118 ||
        sps->profile_idc == 128 || sps->profile_idc == 138 || sps->profile_idc == 139 ||
        sps->profile_idc == 134)
    {
        sps->chroma_format_idc = NALBitReader_read_ue(br);
        if (sps->chroma_format_idc == 3) {
            sps->separate_colour_plane_flag       = NALBitReader_read_bits(br, 1);
        }

        sps->bit_depth_luma_minus8                = NALBitReader_read_ue(br);
        sps->bit_depth_chroma_minus8              = NALBitReader_read_ue(br);
        sps->qpprime_y_zero_transform_bypass_flag = NALBitReader_read_bits(br, 1);

/*
    struct {
            uint32_t seq_scaling_matrix_present_flag;
            uint32_t scaling_list_4x4[16];
            uint32_t scaling_list_8x8[16];
    } seq_scaling_matrix_present_array[8];
*/
        sps->seq_scaling_matrix_present_flag      = NALBitReader_read_bits(br, 1);
        if (sps->seq_scaling_matrix_present_flag) {
            for (int i = 0; i < ((sps->chroma_format_idc != 3) ? 8 : 12); i++) {
                sps->seq_scaling_matrix_present_array[i].seq_scaling_matrix_present_flag = NALBitReader_read_bits(br, 1);
                if (sps->seq_scaling_matrix_present_array[i].seq_scaling_matrix_present_flag) {
                    if (i < 6) {
                        scaling_list(br, sps, &sps->seq_scaling_matrix_present_array[i].scaling_list_4x4[0],
                            16, &sps->useDefaultScalingMatrixFlag[i]);
                    } else {
                        scaling_list(br, sps, &sps->seq_scaling_matrix_present_array[i].scaling_list_8x8[0],
                            64, &sps->useDefaultScalingMatrixFlag[i - 6]);
                    }
                }
            }
        }
    }

    sps->log2_max_frame_num_minus4 = NALBitReader_read_ue(br);
    sps->pic_order_cnt_type        = NALBitReader_read_ue(br);

    if (sps->pic_order_cnt_type == 0) {
        sps->log2_max_pic_order_cnt_lab_minus4     = NALBitReader_read_ue(br);
    } else if (sps->pic_order_cnt_type == 1) {
        sps->delta_pic_order_always_zero_flag      = NALBitReader_read_bits(br, 1);
        sps->offset_for_non_ref_pic                = NALBitReader_read_se(br);
        sps->offset_for_top_to_bottom_field        = NALBitReader_read_se(br);
        sps->num_ref_frames_in_pic_order_cnt_cycle = NALBitReader_read_ue(br);

        for (unsigned int i = 0; i < sps->num_ref_frames_in_pic_order_cnt_cycle; i++) {
            sps->offset_for_ref_frame[i]           = NALBitReader_read_se(br);
        }
    }

    sps->max_num_ref_frames                   = NALBitReader_read_ue(br);
    sps->gaps_in_frame_num_value_allowed_flag = NALBitReader_read_bits(br, 1);
    sps->pic_width_in_mbs_minus1              = NALBitReader_read_ue(br);
    sps->pic_height_in_map_units_minus1       = NALBitReader_read_ue(br);
    sps->frame_mbs_only_flag                  = NALBitReader_read_bits(br, 1);
    if (!sps->frame_mbs_only_flag) {
        sps->mb_adaptive_frame_field_flag     = NALBitReader_read_bits(br, 1);
    }

    sps->direct_8x8_inference_flag            = NALBitReader_read_bits(br, 1);
    sps->frame_cropping_flag                  = NALBitReader_read_bits(br, 1);
    if (sps->frame_cropping_flag) {
        sps->frame_crop_left_offset           = NALBitReader_read_ue(br);
        sps->frame_crop_right_offset          = NALBitReader_read_ue(br);
        sps->frame_crop_top_offset            = NALBitReader_read_ue(br);
        sps->frame_crop_bottom_offset         = NALBitReader_read_ue(br);
    }

    sps->vui_parameters_present_flag               = NALBitReader_read_bits(br, 1);
    if (sps->vui_parameters_present_flag) {
        sps->vui.aspect_ratio_info_present_flag    = NALBitReader_read_bits(br, 1);
        if (sps->vui.aspect_ratio_info_present_flag) {
            sps->vui.aspect_ratio_idc              = NALBitReader_read_bits(br, 8);

            /* See Table E-1 – Meaning of sample aspect ratio indicator  */
            if (sps->vui.aspect_ratio_idc == 255 /* Extended_SAR */) {
                sps->vui.sar_width                 = NALBitReader_read_bits(br, 16);
                sps->vui.sar_height                = NALBitReader_read_bits(br, 16);
            }
        }

        sps->vui.overscan_info_present_flag        = NALBitReader_read_bits(br, 1);
        if (sps->vui.overscan_info_present_flag) {
            sps->vui.overscan_appropriate_flag     = NALBitReader_read_bits(br, 1);
        }

        sps->vui.video_signal_type_present_flag      = NALBitReader_read_bits(br, 1);
        if (sps->vui.video_signal_type_present_flag) {
            sps->vui.video_format                    = NALBitReader_read_bits(br, 3);
            sps->vui.video_full_range_flag           = NALBitReader_read_bits(br, 1);
            sps->vui.colour_description_present_flag = NALBitReader_read_bits(br, 1);
            if (sps->vui.colour_description_present_flag) {
                sps->vui.colour_primaries            = NALBitReader_read_bits(br, 8);
                sps->vui.transfer_characteristics    = NALBitReader_read_bits(br, 8);
                sps->vui.matrix_coefficients         = NALBitReader_read_bits(br, 8);
            }
        }

        sps->vui.chroma_loc_info_present_flag            = NALBitReader_read_bits(br, 1);
        if (sps->vui.chroma_loc_info_present_flag) {
            sps->vui.chroma_sample_loc_type_top_field    = NALBitReader_read_ue(br);
            sps->vui.chroma_sample_loc_type_bottom_field = NALBitReader_read_ue(br);
        }

        sps->vui.timing_info_present_flag        = NALBitReader_read_bits(br, 1);
        if (sps->vui.timing_info_present_flag) {
            sps->vui.num_units_in_tick           = NALBitReader_read_bits(br, 32);
            sps->vui.time_scale                  = NALBitReader_read_bits(br, 32);
            sps->vui.fixed_frame_rate_flag       = NALBitReader_read_bits(br, 1);
        }

        sps->vui.nal_hrd_parameters_present_flag = NALBitReader_read_bits(br, 1);
        if (sps->vui.nal_hrd_parameters_present_flag) {
            avc_seq_parameter_hrd_parse(br, &sps->vui.hrd_hrd_parameters);
        }

        sps->vui.vcl_hrd_parameters_present_flag = NALBitReader_read_bits(br, 1);
        if (sps->vui.vcl_hrd_parameters_present_flag) {
            avc_seq_parameter_hrd_parse(br, &sps->vui.vcl_hrd_parameters);
        }

        if (sps->vui.nal_hrd_parameters_present_flag || sps->vui.vcl_hrd_parameters_present_flag) {
            sps->vui.low_delay_hrd_flag                      = NALBitReader_read_bits(br, 1);
        }

        sps->vui.pic_struct_present_flag                     = NALBitReader_read_bits(br, 1);
        sps->vui.bitstream_restriction_flag                  = NALBitReader_read_bits(br, 1);
        if (sps->vui.bitstream_restriction_flag) {
            sps->vui.motion_vectors_over_pic_boundaries_flag = NALBitReader_read_bits(br, 1);
            sps->vui.max_bytes_per_pic_denom                 = NALBitReader_read_ue(br);
            sps->vui.max_bits_per_mb_denom                   = NALBitReader_read_ue(br);
            sps->vui.log2_max_mv_length_horizontal           = NALBitReader_read_ue(br);
            sps->vui.log2_max_mv_length_vertical             = NALBitReader_read_ue(br);
            sps->vui.max_num_reorder_frames                  = NALBitReader_read_ue(br);
            sps->vui.max_dec_frame_buffering                 = NALBitReader_read_ue(br);
        }
    }

    return 0;
}