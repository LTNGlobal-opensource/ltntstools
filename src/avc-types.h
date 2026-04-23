/* Copyright Kernel Labs Inc 2015-2018 */

#ifndef AVC_TYPES_H
#define AVC_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>

#include <libltntstools/nal_bitreader.h>
#include <libltntstools/nals.h>
#include <libltntstools/nal_h264.h>

struct avc_pic_parameter_set_s;
struct avc_sps_parameter_set_s;
struct avc_slice_header_s;

struct avc_hrd_parameters_s
{
    uint32_t cpb_cnt_minus1;
    uint32_t bit_rate_scale;
    uint32_t cpb_size_scale;
    struct {
        uint32_t bit_rate_value_minus1;
        uint32_t cpb_size_value_minus1;
        uint32_t cbr_flag;
    } cpb_array[256];
    uint32_t initial_cpb_removal_delay_length_minus1;
    uint32_t cpb_removal_delay_length_minus1;
    uint32_t dpb_output_delay_length_minus1;
    uint32_t time_offset_length;
};

/* See ISO-14496-10:2014 7.3.2.1.1 Sequence parameter set data syntax */
struct avc_seq_parameter_set_s
{
    uint32_t profile_idc;
    uint32_t constraint_set0_flag;
    uint32_t constraint_set1_flag;
    uint32_t constraint_set2_flag;
    uint32_t constraint_set3_flag;
    uint32_t constraint_set4_flag;
    uint32_t constraint_set5_flag;
    uint32_t reserved_zero_2bits;
    uint32_t level_idc;
    uint32_t seq_parameter_set_id;

    uint32_t chroma_format_idc;
    uint32_t separate_colour_plane_flag;
    uint32_t bit_depth_luma_minus8;
    uint32_t bit_depth_chroma_minus8;
    uint32_t qpprime_y_zero_transform_bypass_flag;
    uint32_t seq_scaling_matrix_present_flag;
    struct {
            uint32_t seq_scaling_matrix_present_flag;
            uint32_t scaling_list_4x4[16];
            uint32_t scaling_list_8x8[64];
    } seq_scaling_matrix_present_array[8];
    uint32_t useDefaultScalingMatrixFlag[12];

    uint32_t log2_max_frame_num_minus4;
    uint32_t pic_order_cnt_type;

    // if( pic_order_cnt_type = = 0 )
    uint32_t log2_max_pic_order_cnt_lab_minus4;

    // else if( pic_order_cnt_type = = 0 )
    uint32_t delta_pic_order_always_zero_flag;
    uint32_t offset_for_non_ref_pic;
    uint32_t offset_for_top_to_bottom_field;

    uint32_t num_ref_frames_in_pic_order_cnt_cycle;
    // for( i = 0; i < num_ref_frames_in_pic_order_cnt_cycle; i++ )
    uint32_t offset_for_ref_frame[256];
    // end for

    uint32_t max_num_ref_frames;
    uint32_t gaps_in_frame_num_value_allowed_flag;
    uint32_t pic_width_in_mbs_minus1;
    uint32_t pic_width_in_mbs; /* derived */
    uint32_t pic_height_in_map_units_minus1;
    uint32_t pic_height_in_map_units; /* derived */
    uint32_t frame_mbs_only_flag;

    // if( !frame_mbs_only_flag ) {
    uint32_t mb_adaptive_frame_field_flag;
    // }

    uint32_t direct_8x8_inference_flag;
    uint32_t frame_cropping_flag;

    // if( frame_cropping_flag ) {
    uint32_t frame_crop_left_offset;
    uint32_t frame_crop_right_offset;
    uint32_t frame_crop_top_offset;
    uint32_t frame_crop_bottom_offset;
    // }

    uint32_t vui_parameters_present_flag;
    struct {
        uint32_t aspect_ratio_info_present_flag;
        uint32_t aspect_ratio_idc;
        uint32_t sar_width;
        uint32_t sar_height;

        uint32_t overscan_info_present_flag;
        uint32_t overscan_appropriate_flag;

        uint32_t video_signal_type_present_flag;
        uint32_t video_format;
        uint32_t video_full_range_flag;
        uint32_t colour_description_present_flag;
        uint32_t colour_primaries;
        uint32_t transfer_characteristics;
        uint32_t matrix_coefficients;

        uint32_t chroma_loc_info_present_flag;
        uint32_t chroma_sample_loc_type_top_field;
        uint32_t chroma_sample_loc_type_bottom_field;

        uint32_t timing_info_present_flag;
        uint32_t num_units_in_tick ;
        uint32_t time_scale;
        uint32_t fixed_frame_rate_flag;

        uint32_t nal_hrd_parameters_present_flag;
        // if( nal_hrd_parameters_present_flag ) {
        struct avc_hrd_parameters_s hrd_hrd_parameters;
        // }

        uint32_t vcl_hrd_parameters_present_flag;
        // if( vcl_hrd_parameters_present_flag ) {
        struct avc_hrd_parameters_s vcl_hrd_parameters;
        // }

        // if( nal_hrd_parameters_present_flag | | vcl_hrd_parameters_present_flag ) {
        uint32_t low_delay_hrd_flag;
        // }

        uint32_t pic_struct_present_flag;
        uint32_t bitstream_restriction_flag;
        uint32_t motion_vectors_over_pic_boundaries_flag;
        uint32_t max_bytes_per_pic_denom;
        uint32_t max_bits_per_mb_denom;
        uint32_t log2_max_mv_length_horizontal;
        uint32_t log2_max_mv_length_vertical;
        uint32_t max_num_reorder_frames;
        uint32_t max_dec_frame_buffering;
    } vui;
};
struct avc_seq_parameter_set_s *avc_seq_parameter_set_alloc();
void avc_seq_parameter_set_free(struct avc_seq_parameter_set_s *sps);
int  avc_seq_parameter_parse(struct avc_seq_parameter_set_s *sps, const uint8_t *buf, int lengthBytes);
void scaling_list(NALBitReader *br, struct avc_seq_parameter_set_s *sps, uint32_t *scaling_list, int sizeOfScalingList, uint32_t *useDefaultScalingMatrixFlag);

/* See ISO-14496-10:2014 7.3.3 Slice header syntax */
struct avc_slice_header_s
{
    uint32_t first_mb_in_slice;
    uint32_t slice_type;
    uint32_t pic_parameter_set_id;

    // if( separate_colour_plane_flag = = 1 ) {
    uint32_t colour_plane_id;
    // }

    uint32_t frame_num;

    // if( !frame_mbs_only_flag ) {
    uint32_t field_pic_flag;
    // if( field_pic_flag ) {
    uint32_t bottom_field_flag;
    // }
    // }

    // if( IdrPicFlag ) {
    uint32_t idr_pic_id;
    // }

    // if( pic_order_cnt_type = = 0 ) {
    uint32_t pic_order_cnt_lsb;
    uint32_t delta_pic_order_cnt_bottom;
    // }

    uint32_t delta_pic_order_cnt[256]; /* TODO: how big should this really be? */ 

    // if( pic_order_cnt_type = = 1 && !delta_pic_order_always_zero_flag ) {
    // }

    // if( redundant_pic_cnt_present_flag ) {
    uint32_t redundant_pic_cnt;
    // }

    // if( slice_type = = B ) {
    uint32_t direct_spatial_mv_pred_flag;
    // }

    // if( slice_type = = P | | slice_type = = SP | | slice_type = = B ) {
    uint32_t num_ref_idx_active_override_flag;
    uint32_t num_ref_idx_l0_active_minus1;
    uint32_t num_ref_idx_l1_active_minus1;
    // }

    // if( nal_unit_type = = 20 | | nal_unit_type = = 21 ) {
    // TODO: ref_pic_list_mvc_modification( )
    // } else {
    // TODO: ref_pic_list_modification( )
    //}

    // if( ( weighted_pred_flag && ( slice_type == P || slice_type == SP )) || (weighted_bipred_idc == 1 && slice_type == B )) {
    // TODO: pred_weight_table( )
    // }

    // if( nal_ref_idc != 0 ) {
    // TODO: dec_ref_pic_marking( )
    // }

    // if( entropy_coding_mode_flag && slice_type != I && slice_type != SI ) {
    uint32_t cabac_init_idc;
    // }

    uint32_t slice_qp_delta;
    // if( slice_type = = SP | | slice_type = = SI ) {
    uint32_t sp_for_switch_flag;
    uint32_t slice_qs_delta;
    // }

    // if( deblocking_filter_control_present_flag ) {
    uint32_t disable_deblocking_filter_idc;
    uint32_t slice_alpha_c0_offset_div2;
    uint32_t slice_beta_offset_div2;
    // }

    // if( num_slice_groups_minus1 > 0 && slice_group_map_type >= 3 && slice_group_map_type <= 5) {
    uint32_t slice_group_change_cycle;
    // }
};

struct avc_slice_header_s *avc_slice_header_alloc();
void avc_slice_header_free(struct avc_slice_header_s *sh);
int  avc_slice_header_parse(struct avc_seq_parameter_set_s *sps, struct avc_pic_parameter_set_s *pps,
    struct avc_slice_header_s *sh, int nal_unit_type, const uint8_t *buf, int lengthBytes);

/* See ISO-14496-10:2014 7.3.2.2 Picture parameter set RBSP syntax */
struct avc_pic_parameter_set_s
{
    uint32_t pic_parameter_set_id;
    uint32_t seq_parameter_set_id;
    uint32_t entropy_coding_mode_flag;
    uint32_t bottom_field_pic_order_in_frame_present_flag;
    uint32_t num_slice_groups_minus1;

    // if( num_slice_groups_minus1 > 0 ) {
    uint32_t slice_group_map_type;
    struct {
        uint32_t run_length_minus1;
        uint32_t top_left;
        uint32_t bottom_right;
    } slice_groups[255];
    // }

    uint32_t slice_group_change_direction_flag;
    uint32_t slice_group_change_rate_minus1;
    uint32_t pic_size_in_map_units_minus1;
    uint32_t slice_group_id[16];

    uint32_t num_ref_idx_l0_default_active_minus1;
    uint32_t num_ref_idx_l1_default_active_minus1;
    uint32_t weighted_pred_flag;
    uint32_t weighted_bipred_idc;
    uint32_t pic_init_qp_minus26;
    uint32_t pic_init_qs_minus26;
    uint32_t chroma_qp_index_offset;
    uint32_t deblocking_filter_control_present_flag;
    uint32_t constrained_intra_pred_flag;
    uint32_t redundant_pic_cnt_present_flag;

    // if( more_rbsp_data( ) ) {
    uint32_t transform_8x8_mode_flag;
    uint32_t pic_scaling_matrix_present_flag;
    struct {
            uint32_t pic_scaling_list_present_flag;
            uint32_t scaling_list_4x4[16];
            uint32_t scaling_list_8x8[64];
    } pic_scaling_matrix_present_array[8];
    uint32_t useDefaultScalingMatrixFlag[12];

    uint32_t second_chroma_qp_index_offset;
};

struct avc_pic_parameter_set_s *avc_pic_parameter_set_alloc();
void avc_pic_parameter_set_free(struct avc_pic_parameter_set_s *pps);
int  avc_pic_parameter_parse(struct avc_seq_parameter_set_s *sps, struct avc_pic_parameter_set_s *pps, const uint8_t *buf, int lengthBytes);

int avc_core_alloc(void **handle);
int avc_core_decode(void *handle, struct ltn_nal_headers_s *h);
void avc_core_free(void *ctx);

#endif /* AVC_TYPES_H */
