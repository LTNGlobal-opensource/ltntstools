/* Copyright Kernel Labs Inc 2015-2018 */

#include "avc-types.h"

struct avc_pic_parameter_set_s *avc_pic_parameter_set_alloc()
{
    return calloc(1, sizeof(struct avc_pic_parameter_set_s));
}

void avc_pic_parameter_set_free(struct avc_pic_parameter_set_s *pps)
{
    free(pps);
}

/* See ISO/IEC 14496-10:2014(E) - 7.3.2.1.1 Sequence parameter set data syntax */

/* This ALWAYS assumes the RBP stripped has taken place BEFORE hand,
 * See ltn_nal_h264_strip_emulation_prevention(struct ltn_nal_headers_s *h) if you need that.
 */
int avc_pic_parameter_parse(struct avc_seq_parameter_set_s *sps, struct avc_pic_parameter_set_s *pps, const uint8_t *buf, int lengthBytes)
{
    NALBitReader sbr, *br = &sbr;

    NALBitReader_init(br, buf, lengthBytes);

    memset(pps, 0, sizeof(*pps));

    pps->pic_parameter_set_id = NALBitReader_read_ue(br);
    pps->seq_parameter_set_id = NALBitReader_read_ue(br);
    pps->entropy_coding_mode_flag = NALBitReader_read_bits(br, 1);
    pps->num_slice_groups_minus1  = NALBitReader_read_ue(br);
    if (pps->num_slice_groups_minus1 > 0) {
        pps->slice_group_map_type = NALBitReader_read_ue(br);
        if (pps->slice_group_map_type == 0 ) {
            for (uint32_t iGroup = 0; iGroup <= pps->num_slice_groups_minus1; iGroup++) {
                pps->slice_groups[iGroup].run_length_minus1 = NALBitReader_read_ue(br);
            }
        } else if (pps->slice_group_map_type == 2) {
            for (uint32_t iGroup = 0; iGroup < pps->num_slice_groups_minus1; iGroup++) {
                pps->slice_groups[iGroup].top_left = NALBitReader_read_ue(br);
                pps->slice_groups[iGroup].bottom_right = NALBitReader_read_ue(br);
            }
        } else if (pps->slice_group_map_type == 3 || pps->slice_group_map_type == 4 || pps->slice_group_map_type == 5) {
            pps->slice_group_change_direction_flag = NALBitReader_read_bits(br, 1);
            pps->slice_group_change_rate_minus1 = NALBitReader_read_ue(br);
        } else if (pps->slice_group_map_type == 6) {
            pps->pic_size_in_map_units_minus1 = NALBitReader_read_ue(br);
            for (uint32_t i = 0; i <= pps->pic_size_in_map_units_minus1; i++) {
                pps->slice_group_id[i] = NALBitReader_read_bits(br, 1);  // TODO  - FIX ME!
            }
        }
    }

    pps->num_ref_idx_l0_default_active_minus1 = NALBitReader_read_ue(br);
    pps->num_ref_idx_l1_default_active_minus1 = NALBitReader_read_ue(br);
    pps->weighted_pred_flag = NALBitReader_read_bits(br, 1);
    pps->weighted_bipred_idc = NALBitReader_read_bits(br, 2);
    pps->pic_init_qp_minus26 = NALBitReader_read_se(br);
    pps->pic_init_qs_minus26 = NALBitReader_read_se(br);
    pps->chroma_qp_index_offset = NALBitReader_read_se(br);
    pps->deblocking_filter_control_present_flag = NALBitReader_read_bits(br, 1);
    pps->constrained_intra_pred_flag = NALBitReader_read_bit(br);
    pps->redundant_pic_cnt_present_flag = NALBitReader_read_bit(br);

#if 0
    // if( more_rbsp_data( ) ) {
        // TODO:
    // }

#else
    pps->transform_8x8_mode_flag = NALBitReader_read_bit(br);
    pps->pic_scaling_matrix_present_flag = NALBitReader_read_bit(br);
    if (pps->pic_scaling_matrix_present_flag) {
        for (uint32_t i = 0; i < 6 + ((sps->chroma_format_idc != 3) ? 2 : 6) * pps->transform_8x8_mode_flag; i++) {
            pps->pic_scaling_matrix_present_array[i].pic_scaling_list_present_flag = NALBitReader_read_bit(br);
            if (pps->pic_scaling_matrix_present_array[i].pic_scaling_list_present_flag) {
                if (i < 6) {
                    scaling_list(br, sps, &pps->pic_scaling_matrix_present_array[i].scaling_list_4x4[0],
                        16, &pps->useDefaultScalingMatrixFlag[i]);
                } else {
                    scaling_list(br, sps, &pps->pic_scaling_matrix_present_array[i].scaling_list_8x8[0],
                        64, &pps->useDefaultScalingMatrixFlag[i - 6]);
                }

            }
        }
        pps->second_chroma_qp_index_offset = NALBitReader_read_se(br);
    }
#endif

    return 0;
}
